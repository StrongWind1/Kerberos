"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { DECODER_JS, REPO, installDomParser, loadDecoder, read } = require("./helpers");
const dec = require(`${REPO}/${DECODER_JS}`);

installDomParser();

const EX = dec.EXAMPLES;

/** Replace the text of one <Data Name="…"> element in an example. */
function withField(xml, name, value) {
  const re = new RegExp(`(<Data Name="${name}">)[^<]*(</Data>)`);
  assert.match(xml, re, `example has no ${name} field`);
  return xml.replace(re, `$1${value}$2`);
}
function warningsOf(xml) {
  return dec.generateWarnings(dec.parseEvent(xml)).join("\n");
}

/* ------------------------------------------------------------------ */
/*  Lookup tables                                                      */
/* ------------------------------------------------------------------ */

test("Ticket Options decodes as KDC options, not ticket flags", () => {
  const names = (hex) => dec.decodeKdcOptions(hex).map((o) => o.name);
  assert.deepEqual(names("0x40810010"), ["forwardable", "renewable", "canonicalize", "renewable-ok"]);
  /* Bit 14 is the S4U2Proxy marker, not "Request-anonymous". */
  assert.deepEqual(names("0x40820000"), ["forwardable", "renewable", "cname-in-addl-tkt"]);
  assert.deepEqual(names("0x00008000"), ["request-anonymous"]);
  assert.deepEqual(names("0x2"), ["renew"]);
  assert.deepEqual(names("0x0"), []);
  /* Positions that are ticket flags but not KDC options are marked unused. */
  for (const bit of [7, 9, 10, 12, 13]) {
    const hex = "0x" + ((1 << (31 - bit)) >>> 0).toString(16);
    const [o] = dec.decodeKdcOptions(hex);
    assert.equal(o.unused, true, `bit ${bit}`);
    assert.equal(o.name, `unused${bit}`);
  }
  assert.equal(dec.decodeKdcOptions("0x00000020")[0].name, "disable-transited-check", "bit 26, counted from the most significant bit");
  assert.equal(dec.decodeKdcOptions("0x00000800")[0].name, "unassigned", "bit 20 has no meaning");
});

test("malformed Ticket Options are reported, not shown as 'none set'", () => {
  for (const bad of ["zz", "0x4081 0010", "", "0x1FFFFFFFF"]) {
    assert.equal(dec.decodeKdcOptions(bad), null, JSON.stringify(bad));
  }
});

test("result codes follow RFC 4120 / 4556 / 6113 numbering", () => {
  const name = (hex) => dec.decodeResultCode(hex).name;
  assert.equal(name("0x0"), "KDC_ERR_NONE");
  assert.equal(name("0xE"), "KDC_ERR_ETYPE_NOSUPP");
  assert.equal(name("0x11"), "KDC_ERR_TRTYPE_NOSUPP");
  assert.equal(name("0x14"), "KDC_ERR_TGT_REVOKED");
  assert.equal(name("0x1B"), "KDC_ERR_MUST_USE_USER2USER");
  assert.equal(name("0x1C"), "KDC_ERR_PATH_NOT_ACCEPTED");
  assert.equal(name("0x21"), "KRB_AP_ERR_TKT_NYV");
  assert.equal(name("0x42"), "KDC_ERR_CERTIFICATE_MISMATCH");
  assert.equal(name("0x43"), "KRB_AP_ERR_NO_TGT");
  assert.equal(name("0x44"), "KDC_ERR_WRONG_REALM");
  assert.equal(name("0x45"), "KRB_AP_ERR_USER_TO_USER_REQUIRED");
  assert.equal(name("0x4B"), "KDC_ERR_CLIENT_NAME_MISMATCH");
  assert.equal(name("0x5A"), "KDC_ERR_PREAUTH_EXPIRED");
  assert.equal(name("0x5D"), "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS");
  assert.match(name("0x7F"), /^Unknown error \(0x7F\)$/);
  /* Every code from 70 to 81 (PKINIT) is known. */
  for (let c = 70; c <= 81; c++) assert.doesNotMatch(name("0x" + c.toString(16)), /Unknown/, String(c));
  /* The spelling the rest of the site uses. */
  assert.equal(JSON.stringify(dec.RESULT_CODES).includes("ETYPE_NOTSUPP"), false);
});

test("numeric fields that do not fit 32 bits are not silently wrapped", () => {
  assert.ok(Number.isNaN(dec.parseHex("0x1FFFFFFFF")));
  assert.match(dec.decodeEncryptionType("0x100000012").name, /unparseable/);
  assert.match(dec.decodeResultCode("0x100000000").name, /unparseable/);
  assert.equal(dec.decodeEncryptionType("0xffffffff").name, "(Failure)");
  assert.equal(dec.decodeEncryptionType("0x12").name, "AES256-CTS-HMAC-SHA1-96");
  assert.equal(dec.decodeEncryptionType("0xFFFFFF80").name, "RC4-MD4");
});

test("lookups are not fooled by Object.prototype keys", () => {
  assert.equal(dec.fieldLabel("constructor", 4768), "constructor");
  assert.equal(dec.fieldLabel("toString", 4769), "toString");
  assert.equal(dec.fieldLabel("Status", 4768), "Result Code");
  assert.equal(dec.fieldLabel("Status", 4769), "Failure Code");
  assert.equal(dec.fieldLabel("Status", 4771), "Failure Code");
  const xml = EX["4769-success"].replace('<Data Name="TicketOptions">', '<Data Name="constructor">x</Data><Data Name="TicketOptions">');
  const t = loadDecoder();
  t.$("#evdec-xml").value = xml;
  t.$("#evdec-decode").click();
  assert.deepEqual(t.errors, []);
  assert.doesNotMatch(t.$("#evdec-fields").textContent, /function Object|\[native code\]/);
});

test("AES-SHA2 etypes carry the one agreed status", () => {
  for (const hex of ["0x13", "0x14"]) {
    assert.match(dec.decodeEncryptionType(hex).note,
      /supported on Windows 11 24H2 \/ Server 2025, disabled by default \(MS-KILE §2\.2\.7\); not lab-tested on this site/);
  }
});

test("SupportedEncryptionTypes fields decode to flag names", () => {
  assert.deepEqual(dec.parseSetField("0x27 (DES, RC4, AES-Sk)"),
    { value: 0x27, names: ["DES-CBC-CRC", "DES-CBC-MD5", "RC4-HMAC", "AES256-CTS-HMAC-SHA1-96-SK"] });
  assert.equal(dec.parseSetField("N/A"), null);
  assert.equal(dec.parseSetField(""), null);
  assert.match(dec.parseSetField("0x80000018").names.join(), /0x80000000 \(undefined bits\)/);
});

/* ------------------------------------------------------------------ */
/*  Input formats                                                      */
/* ------------------------------------------------------------------ */

test("every built-in example parses and summarises", () => {
  const expected = {
    "4768-success": [4768, "success", 24],
    "4768-failure": [4768, "failure", 14],
    "4769-success": [4769, "success", 21],
    "4771-failure": [4771, "failure", 11],
    "4770-renew": [4770, "success", 8],
  };
  assert.deepEqual(Object.keys(EX).sort(), Object.keys(expected).sort());
  for (const [key, [id, outcome, fieldCount]] of Object.entries(expected)) {
    const p = dec.parseEvent(EX[key]);
    assert.equal(p.eventId, id, key);
    assert.equal(p.format, "xml", key);
    assert.equal(dec.eventOutcome(p), outcome, key);
    assert.equal(p.fieldOrder.length, fieldCount, key);
    assert.match(dec.buildCopyText(p), new RegExp(`^Kerberos Event ${id} `), key);
  }
});

test("XML is found whatever surrounds it", () => {
  const xml = EX["4769-success"];
  const variants = {
    "CRLF + BOM": "﻿" + xml.replace(/></g, ">\r\n<"),
    "XML declaration": '<?xml version="1.0" encoding="utf-8"?>\n' + xml,
    "Copy details as text": "Log Name:      Security\nEvent ID:      4769\nDescription:\nA Kerberos service ticket was requested.\n\nEvent Xml:\n" + xml,
    "<Events> wrapper": "<Events>" + xml + EX["4768-success"] + "</Events>",
    "leading prose": "here is the event from DC1:\n\n" + xml,
    "XML view node markers": xml.replace(/></g, ">\n- <").replace(/^/, "- "),
    "indented node markers": xml.replace(/></g, ">\n  - <").replace(/^/, "  - "),
    "HTML-escaped": xml.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"),
    "two events": xml + "\n" + EX["4771-failure"],
  };
  for (const [label, input] of Object.entries(variants)) {
    const p = dec.parseEvent(input);
    assert.equal(p.eventId, 4769, label);
    assert.equal(p.fields.ServiceName, "DC1$", label);
    assert.equal(p.fields.TicketOptions, "0x40800000", label);
  }
});

test("broken input gets a specific message", () => {
  const msg = (input) => {
    try { dec.parseEvent(input); } catch (e) { assert.equal(e.isDecodeError, true, input.slice(0, 30)); return e.message; }
    return assert.fail("expected an error for " + input.slice(0, 30));
  };
  const xml = EX["4768-success"];
  assert.match(msg(xml.replace("</Event>", "")), /no closing <\/Event> tag/);
  assert.match(msg(xml.replace("<Event ", "<event ").replace("</Event>", "</event>")), /case-sensitive/);
  assert.match(msg('<!DOCTYPE x [<!ENTITY e "x">]>' + xml.replace("<Event ", "<Event a='&e;' ")), /Invalid XML/);
  assert.match(msg(xml.replace("<Event ", '<Event><!DOCTYPE x>')), /DOCTYPE/);
  assert.match(msg(xml.replace("<EventID>4768", "<EventID>4624")), /Unsupported event ID: 4624/);
  assert.match(msg(xml.replace("<EventID>4768", "<EventID>4773")), /Windows does not generate it/);
  assert.match(msg(xml.replace("</EventData>", "</EventDataX>")), /Invalid XML/);
  assert.match(msg("hello world"), /does not look like a Kerberos event/);
  assert.match(msg("Service Name: svc\nTicket Options: 0x40810010"), /Could not tell which event/);
});

const TEXT_4769 = [
  "A Kerberos service ticket was requested.",
  "",
  "Account Information:",
  "\tAccount Name:\t\talice@CORP.LOCAL",
  "\tAccount Domain:\t\tCORP.LOCAL",
  "\tLogon GUID:\t\t{00000000-0000-4000-8000-000000000001}",
  "\tMSDS-SupportedEncryptionTypes:\tN/A",
  "\tAvailable Keys:\tN/A",
  "",
  "Service Information:",
  "\tService Name:\t\tsvc_app01",
  "\tService ID:\t\tS-1-5-21-1-2-3-1105",
  "\tMSDS-SupportedEncryptionTypes:\t0x27 (DES, RC4, AES-Sk)",
  "\tAvailable Keys:\tAES-SHA1, RC4",
  "",
  "Domain Controller Information:",
  "\tMSDS-SupportedEncryptionTypes:\t0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
  "\tAvailable Keys:\tAES-SHA1, RC4",
  "",
  "Network Information:",
  "\tClient Address:\t\t::ffff:192.0.2.100",
  "\tClient Port:\t\t50123",
  "\tAdvertized Etypes:\t",
  "\t\tAES256-CTS-HMAC-SHA1-96",
  "\t\tAES128-CTS-HMAC-SHA1-96",
  "\t\tRC4-HMAC-NT",
  "",
  "Additional Information:",
  "\tTicket Options:\t\t0x40810000",
  "\tTicket Encryption Type:\t0x17",
  "\tSession Encryption Type:\t0x12",
  "\tFailure Code:\t\t0x0",
  "\tTransited Services:\t-",
  "",
  "Ticket information",
  "\tRequest ticket hash:\t\tabc=",
  "\tResponse ticket hash:\t\tdef=",
  "",
  "This event is generated every time access is requested to a resource.",
].join("\r\n");

test("the Event Viewer text rendering parses, section by section", () => {
  const p = dec.parseEvent(TEXT_4769);
  assert.equal(p.format, "text");
  assert.equal(p.eventId, 4769);
  const f = p.fields;
  assert.equal(f.TargetUserName, "alice@CORP.LOCAL");
  assert.equal(f.AccountSupportedEncryptionTypes, "N/A");
  assert.equal(f.ServiceSupportedEncryptionTypes, "0x27 (DES, RC4, AES-Sk)");
  assert.equal(f.ServiceAvailableKeys, "AES-SHA1, RC4");
  assert.equal(f.DCSupportedEncryptionTypes, "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)");
  assert.equal(f.IpAddress, "::ffff:192.0.2.100", "IPv6 colons stay in the value");
  assert.equal(f.ClientAdvertizedEncryptionTypes, "AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 RC4-HMAC-NT");
  assert.equal(f.TicketEncryptionType, "0x17");
  assert.equal(f.SessionKeyEncryptionType, "0x12");
  assert.equal(f.Status, "0x0");
  assert.equal(f.ResponseTicketHash, "def=");
  assert.equal(dec.eventOutcome(p), "success");
});

test("the abridged sample format used on this site parses", () => {
  const sample = [
    "Event ID:                         4769",
    "Service Name:                     svc_app01",
    "MSDS-SupportedEncryptionTypes:    0x27 (DES, RC4, AES-Sk)",
    "Available Keys:                   AES-SHA1, RC4",
    "Advertized Etypes:                AES256-CTS-HMAC-SHA1-96",
    "Ticket Encryption Type:           0x17",
    "Session Encryption Type:          0x12",
  ].join("\n");
  const p = dec.parseEvent(sample);
  assert.equal(p.eventId, 4769);
  assert.equal(p.fields.ServiceSupportedEncryptionTypes, "0x27 (DES, RC4, AES-Sk)", "section inferred from Service Name");
  assert.equal(p.fields.ServiceAvailableKeys, "AES-SHA1, RC4");
  assert.equal(dec.eventOutcome(p), "unknown", "no status line in the excerpt");
});

test("Format-List output parses", () => {
  const fl = [
    "TimeCreated  : 4/7/2026 6:00:54 AM",
    "Id           : 4771",
    "MachineName  : DC1.contoso.local",
    "Message      : Kerberos pre-authentication failed.",
    "               ",
    "               Account Information:",
    "               \tSecurity ID:\t\tS-1-5-21-1-2-3-500",
    "               \tAccount Name:\t\tAdministrator",
    "               ",
    "               Service Information:",
    "               \tService Name:\t\tkrbtgt/CONTOSO",
    "               ",
    "               Additional Information:",
    "               \tTicket Options:\t\t0x40810010",
    "               \tFailure Code:\t\t0x18",
    "               \tPre-Authentication Type:\t2",
  ].join("\n");
  const p = dec.parseEvent(fl);
  assert.equal(p.eventId, 4771);
  assert.equal(p.computer, "DC1.contoso.local");
  assert.equal(p.time, "4/7/2026 6:00:54 AM");
  assert.equal(p.fields.TargetUserName, "Administrator");
  assert.equal(p.fields.Status, "0x18");
  assert.equal(p.fields.PreAuthType, "2");
});

test("Format-List * output: the record's UserId property is not the 4768 User ID field", () => {
  const fl = [
    "Message              : A Kerberos service ticket was requested.",
    "                       ",
    "                       Account Information:",
    "                       \tAccount Name:\t\talice@CORP.LOCAL",
    "                       \tAccount Domain:\t\tCORP.LOCAL",
    "                       ",
    "                       Service Information:",
    "                       \tService Name:\t\tsvc_app01",
    "                       ",
    "                       Additional Information:",
    "                       \tTicket Options:\t\t0x40810000",
    "                       \tTicket Encryption Type:\t0x12",
    "                       \tFailure Code:\t\t0x0",
    "Id                   : 4769",
    "Version              : 2",
    "RecordId             : 883211",
    "ProviderName         : Microsoft-Windows-Security-Auditing",
    "LogName              : Security",
    "ProcessId            : 716",
    "MachineName          : dc1.corp.local",
    "UserId               : ",
    "TimeCreated          : 11/9/2026 2:14:07 PM",
  ].join("\n");
  const p = dec.parseEvent(fl);
  assert.equal(p.eventId, 4769);
  assert.equal(p.computer, "dc1.corp.local");
  assert.equal(p.fieldOrder.includes("TargetSid"), false, "no spurious Account SID row");
  assert.deepEqual(p.batch, { count: 1, index: 0, incomplete: false });
  assert.deepEqual(dec.inputNotices(p), []);

  /* The real field of a 4768 is still read. */
  const tgt = dec.parseEvent("A Kerberos authentication ticket (TGT) was requested.\n\nAccount Information:\n\tAccount Name:\t\talice\n\tSupplied Realm Name:\tCORP.LOCAL\n\tUser ID:\t\t\tS-1-5-21-1111111111-2222222222-3333333333-1104\n");
  assert.equal(tgt.fields.TargetSid, "S-1-5-21-1111111111-2222222222-3333333333-1104");
});

/* ------------------------------------------------------------------ */
/*  More than one event in the paste                                   */
/* ------------------------------------------------------------------ */

/* Two events as Event Viewer's "Copy details as text" writes them when the
   XML is left out: a 4771 failure followed by a 4769 success. */
const TEXT_4771 = [
  "Log Name:      Security",
  "Source:        Microsoft-Windows-Security-Auditing",
  "Date:          11/9/2026 2:14:07 PM",
  "Event ID:      4771",
  "Task Category: Kerberos Authentication Service",
  "Level:         Information",
  "Keywords:      Audit Failure",
  "User:          N/A",
  "Computer:      dc1.corp.local",
  "Description:",
  "Kerberos pre-authentication failed.",
  "",
  "Account Information:",
  "\tSecurity ID:\t\tCORP\\alice",
  "\tAccount Name:\t\talice",
  "",
  "Service Information:",
  "\tService Name:\t\tkrbtgt/CORP",
  "",
  "Network Information:",
  "\tClient Address:\t\t::ffff:192.0.2.41",
  "\tClient Port:\t\t50400",
  "",
  "Additional Information:",
  "\tTicket Options:\t\t0x40810010",
  "\tFailure Code:\t\t0x18",
  "\tPre-Authentication Type:\t2",
  "",
  "Certificate Information:",
  "\tCertificate Issuer Name:\t\t",
  "\tCertificate Serial Number: \t",
  "\tCertificate Thumbprint:\t\t",
  "",
  "Certificate information is only provided if a certificate was used for pre-authentication.",
].join("\n");

const TEXT_4769_WITH_HEADER = [
  "Log Name:      Security",
  "Source:        Microsoft-Windows-Security-Auditing",
  "Date:          11/9/2026 2:15:31 PM",
  "Event ID:      4769",
  "Task Category: Kerberos Service Ticket Operations",
  "Level:         Information",
  "Keywords:      Audit Success",
  "User:          N/A",
  "Computer:      dc1.corp.local",
  "Description:",
].join("\n") + "\n" + TEXT_4769.replace(/\r\n/g, "\n");

test("two text events pasted together are not merged into one", () => {
  const p = dec.parseEvent(TEXT_4771 + "\n\n" + TEXT_4769_WITH_HEADER);
  assert.equal(p.eventId, 4771);
  assert.equal(p.time, "11/9/2026 2:14:07 PM");
  assert.equal(p.fields.TargetUserName, "alice", "the first event's account, not the second's");
  assert.equal(p.fields.Status, "0x18", "the first event's failure code");
  assert.equal(dec.decodeResultCode(p.fields.Status).name, "KDC_ERR_PREAUTH_FAILED");
  /* Nothing of the second event leaks into the first. */
  for (const key of ["TicketEncryptionType", "SessionKeyEncryptionType", "ServiceSupportedEncryptionTypes", "ClientAdvertizedEncryptionTypes", "TransmittedServices", "LogonGuid"]) {
    assert.equal(p.fields[key], undefined, key);
  }
  assert.doesNotMatch(dec.generateWarnings(p).join("\n"), /RC4|AES-SK/);
  assert.deepEqual(p.batch, { count: 2, index: 0, incomplete: false });
  const [notice] = dec.inputNotices(p);
  assert.match(notice, /holds 2 events\. Only one is decoded at a time: this is event 1 of 2\. Paste the others one at a time/);
  assert.match(dec.buildCopyText(p), /^Note: The pasted text holds 2 events/m);

  /* The other order decodes the 4769 and leaves the 4771 out. */
  const q = dec.parseEvent(TEXT_4769_WITH_HEADER + "\n\n" + TEXT_4771);
  assert.equal(q.eventId, 4769);
  assert.equal(q.fields.Status, "0x0");
  assert.equal(q.fields.PreAuthType, undefined);
  assert.equal(q.batch.count, 2);
});

test("text events are split wherever a once-per-event line repeats", () => {
  const general = TEXT_4769.replace(/\r\n/g, "\n");
  const pieces = (text) => dec.splitTextEvents(text).length;
  assert.equal(pieces(general), 1);
  assert.equal(pieces(TEXT_4771), 1);
  assert.equal(pieces(TEXT_4769_WITH_HEADER), 1, "header and description belong to one event");
  /* General tab text has no header: the description sentence starts each event. */
  assert.equal(pieces(general + "\n\n" + general), 2);
  /* The abridged form used on this site has only an Event ID line. */
  const abridged = "Event ID:  4769\nService Name:  svc_app01\nTicket Encryption Type:  0x12\n";
  assert.equal(pieces(abridged + abridged + abridged), 3);
  /* wevtutil /f:text numbers its events. */
  const wevt = (n) => `Event[${n}]:\n  Log Name: Security\n  Date: 2026-11-09T14:14:07.1230000Z\n  Event ID: 4769\n  Computer: dc1.corp.local\n  Description: \nA Kerberos service ticket was requested.\n\nService Information:\n\tService Name:\t\tsvc_app01\n\nAdditional Information:\n\tTicket Options:\t\t0x40810000\n\tFailure Code:\t\t0x0\n`;
  assert.equal(pieces(wevt(0)), 1);
  assert.equal(pieces(wevt(0) + "\n" + wevt(1)), 2);
  /* Format-List: TimeCreated, Id, then Message. */
  const fl = "TimeCreated  : 4/7/2026 6:00:54 AM\nId           : 4771\nMessage      : Kerberos pre-authentication failed.\n               \n               Account Information:\n               \tAccount Name:\t\talice\n               \n               Additional Information:\n               \tFailure Code:\t\t0x18\n";
  assert.equal(pieces(fl), 1);
  assert.equal(pieces(fl + "\n" + fl), 2);
  const second = dec.parseEvent(fl + "\n" + fl.replace("alice", "svc_legacy"));
  assert.equal(second.fields.TargetUserName, "alice");
  assert.equal(second.batch.count, 2);

  /* Prose around one event that repeats a marker is not a second event. */
  const withProse = dec.parseEvent("Kerberos pre-authentication failed on dc1 again, event below.\n\n" + TEXT_4771 + "\n\nDate: please look at this today");
  assert.equal(withProse.eventId, 4771);
  assert.deepEqual(withProse.batch, { count: 1, index: 0, incomplete: false });
  assert.deepEqual(dec.inputNotices(withProse), []);
});

/** A copy of an example with another event ID, as a stand-in for an event the decoder does not handle. */
function otherEvent(id) {
  return EX["4770-renew"].replace("<EventID>4770", `<EventID>${id}`);
}

test("several XML events: one is decoded, and the result says so", () => {
  /* A saved log: <Events> around a 4768, a 4769 and a logon event. */
  let p = dec.parseEvent("<Events>" + EX["4768-success"] + EX["4769-success"] + otherEvent(4624) + "</Events>");
  assert.equal(p.eventId, 4768);
  assert.deepEqual(p.batch, { count: 3, index: 0, incomplete: false });
  assert.match(dec.inputNotices(p)[0], /holds 3 events\. Only one is decoded at a time: this is event 1 of 3\./);

  /* An event of another ID first: the first one the decoder handles is shown, not an error. */
  p = dec.parseEvent('<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>' + otherEvent(4624) + EX["4769-success"] + "</Events>");
  assert.equal(p.eventId, 4769);
  assert.equal(p.fields.ServiceName, "DC1$");
  assert.deepEqual(p.batch, { count: 2, index: 1, incomplete: false });
  assert.match(dec.inputNotices(p)[0], /this is event 2 of 2, the first one that this decoder handles\./);

  /* None supported: the message says how many were found and why the first was rejected. */
  assert.throws(() => dec.parseEvent(otherEvent(4624) + otherEvent(4634)),
    (e) => e.isDecodeError && /holds 2 events and none of them could be decoded\..*Unsupported event ID: 4624/.test(e.message));
  /* A single unsupported event keeps its plain message. */
  assert.throws(() => dec.parseEvent(otherEvent(4624)), (e) => /^Unsupported event ID: 4624/.test(e.message));

  /* A trailing event that was cut off is counted and named. */
  p = dec.parseEvent(EX["4771-failure"] + EX["4769-success"].slice(0, 400));
  assert.equal(p.eventId, 4771);
  assert.deepEqual(p.batch, { count: 2, index: 0, incomplete: true });
  assert.match(dec.inputNotices(p)[0], /holds 2 events \(the last one is cut off\)/);

  /* One event: no notice. */
  p = dec.parseEvent(EX["4769-success"]);
  assert.deepEqual(p.batch, { count: 1, index: 0, incomplete: false });
  assert.deepEqual(dec.inputNotices(p), []);
  assert.doesNotMatch(dec.buildCopyText(p), /^Note:/m);
});

test("non-English event text is told apart from text that is not an event", () => {
  const msg = (input) => {
    try { dec.parseEvent(input); } catch (e) { assert.equal(e.isDecodeError, true); return e.message; }
    return assert.fail("expected an error");
  };
  const german = [
    "Ein Kerberos-Dienstticket wurde angefordert.",
    "",
    "Kontoinformationen:",
    "\tKontoname:\t\talice@CORP.LOCAL",
    "\tKontodomäne:\t\tCORP.LOCAL",
    "",
    "Dienstinformationen:",
    "\tDienstname:\t\tsvc_app01",
    "",
    "Weitere Informationen:",
    "\tTicketoptionen:\t\t0x40810000",
    "\tTicketverschlüsselungstyp:\t0x17",
    "\tFehlercode:\t\t0x0",
    "\tÜbertragene Dienste:\t-",
  ].join("\n");
  const french = [
    "TimeCreated  : 09/11/2026 14:14:07",
    "Id           : 4769",
    "Message      : Un ticket de service Kerberos a été demandé.",
    "               ",
    "               Informations sur le compte :",
    "               \tNom du compte :\t\talice@CORP.LOCAL",
    "               ",
    "               Informations supplémentaires :",
    "               \tOptions du ticket :\t\t0x40810000",
    "               \tType de chiffrement du ticket :\t0x17",
    "               \tCode d’échec :\t\t0xE",
  ].join("\n");
  for (const text of [german, french, "Log Name: Security\nEvent ID: 4769\n" + german]) {
    const m = msg(text);
    assert.match(m, /Only English-language event text is recognised\./);
    assert.match(m, /paste the event XML instead/);
    assert.match(m, /reads the XML by field name, not by the translated labels/);
    assert.doesNotMatch(m, /does not look like a Kerberos event/);
  }
  /* Not event-shaped at all: the general message, which also names the limit. */
  for (const text of ["hello world", "{\"EventID\": 4769}", "TimeCreated  Id LevelDisplayName Message\n11/9/2026 2:14:07 PM  4769 Information  A Kerberos service ticket was requested...."]) {
    const m = msg(text);
    assert.match(m, /^This does not look like a Kerberos event\./);
    assert.match(m, /Only English-language text is recognised/);
  }
  /* The same German event as XML decodes: the XML carries no translated labels. */
  assert.equal(dec.parseEvent("Protokollname: Security\nEreignis-ID:   4769\nBeschreibung:\n" + german + "\n\nEreignis-XML:\n" + EX["4769-success"]).eventId, 4769);
});

/* ------------------------------------------------------------------ */
/*  Warnings                                                           */
/* ------------------------------------------------------------------ */

/* Microsoft's own example of a 0xE failure (learn.microsoft.com, "Detect and
   remediate RC4 usage in Kerberos"), with the names replaced.  Every etype
   field is "-"; the cause in the article is the service account's RC4-only
   attribute, not the client. */
const MS_0XE_TEXT = [
  "A Kerberos service ticket was requested.",
  "Account Information:",
  " Account Name: alice@CORP.LOCAL",
  " Account Domain: CORP.LOCAL",
  " Logon GUID: {00000000-0000-0000-0000-000000000000}",
  " MSDS-SupportedEncryptionTypes: -",
  " Available Keys: -",
  "Service Information:",
  " Service Name: HOST/app01.corp.local",
  " Service ID: NULL SID",
  " MSDS-SupportedEncryptionTypes: -",
  " Available Keys: -",
  "Domain Controller Information:",
  " MSDS-SupportedEncryptionTypes: -",
  " Available Keys: -",
  "Network Information:",
  " Client Address: ::ffff:192.0.2.112",
  " Client Port: 60090",
  " Advertized Etypes: -",
  "Additional Information:",
  " Ticket Options: 0x40810000",
  " Ticket Encryption Type: 0xFFFFFFFF",
  " Session Encryption Type: 0x2D",
  " Failure Code: 0xE",
  " Transited Services: -",
].join("\n");

test("an etype list of \"-\" or \"N/A\" is not read as a client that offers no AES", () => {
  const p = dec.parseEvent(MS_0XE_TEXT);
  assert.equal(p.eventId, 4769);
  assert.equal(p.fields.ClientAdvertizedEncryptionTypes, "-");
  const w = dec.generateWarnings(p).join("\n");
  assert.doesNotMatch(w, /offered no AES|client offered/i);
  assert.doesNotMatch(w, /S4U2Proxy/);
  /* The summary does not present "-" as a list either. */
  assert.equal(dec.buildPipeline(p).some((g) => g.stages.some((s) => s.label === "Client offer")), false);
  assert.match(dec.buildCopyText(p), /^Client offer: +not recorded \(-\)$/m);
  assert.match(dec.buildCopyText(p), /^Service set: +not recorded \(-\)$/m);

  /* The same in XML, on other failure codes, and with N/A. */
  for (const [status, marker] of [["0x1B", "-"], ["0x20", "-"], ["0xD", "-"], ["0xE", "N/A"]]) {
    let xml = withField(EX["4769-success"], "Status", status);
    xml = withField(xml, "TicketEncryptionType", "0xffffffff");
    xml = withField(xml, "ClientAdvertizedEncryptionTypes", marker);
    assert.doesNotMatch(warningsOf(xml), /offered no AES/, `${status} ${marker}`);
  }
  /* A real list without AES is still flagged. */
  assert.match(warningsOf(withField(EX["4769-success"], "ClientAdvertizedEncryptionTypes", "RC4-HMAC-NT")), /offered no AES etype/);
});

test("0xE guidance names fields only when the event has them", () => {
  /* Fields present but "-": Microsoft's example. */
  let w = dec.generateWarnings(dec.parseEvent(MS_0XE_TEXT)).join("\n");
  assert.match(w, /Status 0xE \(KDC_ERR_ETYPE_NOSUPP\): no usable etype\. This event shows "-" for the client's advertised etypes and the target account's SupportedEncryptionTypes and Available Keys/);
  assert.match(w, /Read the target account's msDS-SupportedEncryptionTypes in Active Directory and the client's Kerberos etype policy instead, then check the KDC filter/);
  assert.doesNotMatch(w, /Compare the client's advertised etypes/);

  /* An event from before the fields existed (version 0). */
  const v0 = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4769</EventID><Version>0</Version><TimeCreated SystemTime="2026-11-09T14:14:07.1234567Z"/><Computer>dc1.corp.local</Computer></System><EventData><Data Name="TargetUserName">alice@CORP.LOCAL</Data><Data Name="TargetDomainName">CORP.LOCAL</Data><Data Name="ServiceName">HOST/app01.corp.local</Data><Data Name="ServiceSid">S-1-0-0</Data><Data Name="TicketOptions">0x40810000</Data><Data Name="TicketEncryptionType">0xffffffff</Data><Data Name="IpAddress">::ffff:192.0.2.41</Data><Data Name="IpPort">50432</Data><Data Name="Status">0xE</Data><Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data><Data Name="TransmittedServices">-</Data></EventData></Event>';
  w = warningsOf(v0);
  assert.match(w, /This event has no fields for the client's advertised etypes and the target account's SupportedEncryptionTypes and Available Keys\. Windows Server 2016 and later log them once the January 14, 2025 or a later cumulative update is installed\./);
  assert.doesNotMatch(w, /Compare the client's advertised etypes/);

  /* A 4771 never carries the etype fields; the January 2025 note is about 4768 and 4769. */
  w = warningsOf(withField(EX["4771-failure"], "Status", "0xE"));
  assert.match(w, /Event 4771 has no fields for the client's advertised etypes/);
  assert.doesNotMatch(w, /January 14, 2025/);

  /* With the fields recorded, the comparison is the advice. */
  w = warningsOf(withField(EX["4769-success"], "Status", "0xE"));
  assert.match(w, /Compare the client's advertised etypes with the target account's effective SupportedEncryptionTypes and Available Keys, then check the KDC filter/);
  assert.match(w, /an RC4-only client against an account with no msDS-SupportedEncryptionTypes fails here/);

  /* A TGT request is not explained with the service-ticket rule. */
  w = warningsOf(withField(EX["4768-success"], "Status", "0xE"));
  assert.match(w, /Compare the client's advertised etypes with the Available Keys of the account and of krbtgt, then check the KDC filter/);
  assert.doesNotMatch(w, /target account's effective SupportedEncryptionTypes|April 2026/);
});

test("a requester's 0x27 on a TGT request is not an alarm", () => {
  /* Microsoft's updated 4768 sample: Account set 0x27, AES256 TGT, success. */
  const xml = withField(EX["4768-success"], "AccountSupportedEncryptionTypes", "0x27 (DES, RC4, AES-Sk)");
  const p = dec.parseEvent(xml);
  assert.equal(dec.eventOutcome(p), "success");
  assert.deepEqual(dec.generateWarnings(p), []);
  /* Neither is the DC's own processed value. */
  assert.doesNotMatch(warningsOf(withField(EX["4769-success"], "DCSupportedEncryptionTypes", "0x7 (DES, RC4)")), /lists no AES etype/);
  /* The target of a service ticket still is. */
  assert.match(warningsOf(withField(EX["4769-success"], "ServiceSupportedEncryptionTypes", "0x27 (DES, RC4, AES-Sk)")),
    /Service SupportedEncryptionTypes \(effective\) lists no AES etype \(0x27\)/);
});

test("a TGT request is explained with the AS rules, not the service-ticket rules", () => {
  const tgs = /target account's effective set|Needs an etype present in both|KdcUseRequestedEtypesForTickets/;
  assert.match(dec.fieldSource("TicketEncryptionType", 4769), tgs);
  assert.match(dec.fieldSource("SessionKeyEncryptionType", 4769), tgs);
  assert.match(dec.fieldSource("TicketEncryptionType", 4768), /A TGT is encrypted with one of the krbtgt account's keys, subject to the KDC filter\./);
  assert.match(dec.fieldSource("SessionKeyEncryptionType", 4768), /the strongest etype in the client's list that the KDC allows/);
  assert.doesNotMatch(dec.fieldSource("TicketEncryptionType", 4768) + dec.fieldSource("SessionKeyEncryptionType", 4768), tgs);
  assert.equal(dec.fieldSource("Status", 4768), dec.FIELD_SOURCES.Status, "other fields are shared");
  assert.equal(dec.fieldSource("constructor", 4768), undefined);

  const [ticket, session] = dec.buildPipeline(dec.parseEvent(EX["4768-success"]));
  assert.deepEqual(ticket.stages.map((s) => s.label), ["Target account keys", "KDC filter"]);
  assert.match(ticket.rule, /krbtgt account's keys, subject to the KDC filter/);
  assert.deepEqual(session.stages.map((s) => s.label), ["Client offer", "KDC filter"]);
  assert.match(session.rule, /strongest etype in the client's list that the KDC allows/);
  assert.doesNotMatch(ticket.rule + session.rule, tgs);

  /* An RC4 TGT is not blamed on the target account's effective set. */
  const w = warningsOf(withField(EX["4768-success"], "TicketEncryptionType", "0x17"));
  assert.match(w, /The TGT is encrypted with RC4\. A TGT is encrypted with one of the krbtgt account's keys/);
  assert.doesNotMatch(w, /effective set lists RC4|no longer issue RC4 by default|AES-SK split|Kerberoasting/);

  /* In the page: the 4768 example shows the AS wording, the 4769 example the TGS wording. */
  const t = loadDecoder();
  t.$('.evdec-example-btn[data-example="4768-success"]').click();
  assert.doesNotMatch(t.$("#evdec-fields").textContent + t.$("#evdec-pipeline").textContent, tgs);
  assert.match(t.$("#evdec-pipeline").textContent, /strongest etype in the client's list that the KDC allows/);
  t.$('.evdec-example-btn[data-example="4769-success"]').click();
  assert.match(t.$("#evdec-pipeline").textContent, /Needs an etype present in both/);
});

test("the DC's own set is described as a processed value", () => {
  assert.match(dec.FIELD_SOURCES.DCSupportedEncryptionTypes, /processed value: on Windows Server 2022 and earlier it always shows DES and RC4/);
});

test("no pre-authentication warning on failure events", () => {
  assert.doesNotMatch(warningsOf(EX["4768-failure"]), /pre-authentication/i, "PreAuthType 0 on a 0x6 failure means nothing");
  const locked = withField(withField(EX["4771-failure"], "PreAuthType", "0"), "Status", "0x12");
  assert.doesNotMatch(warningsOf(locked), /without pre-authentication/);
  const roastable = withField(EX["4768-success"], "PreAuthType", "0");
  assert.match(warningsOf(roastable), /issued without pre-authentication/);
});

test("the three 4769 etype diagnostics fire", () => {
  /* AES-SK split */
  let xml = withField(EX["4769-success"], "TicketEncryptionType", "0x17");
  xml = withField(xml, "ServiceSupportedEncryptionTypes", "0x27 (DES, RC4, AES-Sk)");
  assert.match(warningsOf(xml), /AES-SK split: the session key is AES but the ticket is RC4/);
  assert.match(warningsOf(TEXT_4769), /AES-SK split/, "also from the text form");

  /* Ticket etype outside the target's effective set */
  xml = withField(EX["4769-success"], "TicketEncryptionType", "0x17");
  xml = withField(xml, "SessionKeyEncryptionType", "0x17");
  xml = withField(xml, "ServiceSupportedEncryptionTypes", "0x18 (AES128-SHA96, AES256-SHA96)");
  assert.match(warningsOf(xml), /not in the target's effective SupportedEncryptionTypes \(0x18\)/);

  /* AES allowed but no AES keys */
  xml = withField(EX["4769-success"], "ServiceAvailableKeys", "RC4");
  assert.match(warningsOf(xml), /allows AES \(0x1F\) but the account has no AES keys/);

  /* None of them on the clean example. */
  assert.doesNotMatch(warningsOf(EX["4769-success"]), /AES-SK split|not in the target's|no AES keys/);
});

test("an effective set without AES is described accurately", () => {
  const xml = withField(EX["4769-success"], "ServiceSupportedEncryptionTypes", "0x27 (DES, RC4, AES-Sk)");
  const w = warningsOf(xml);
  assert.match(w, /lists no AES etype \(0x27\)/);
  assert.doesNotMatch(w, /will fail authentication if RC4 is blocked/);
  /* The event cannot tell an explicit attribute from the DC's fallback, and
     the filter matrix (includes/kdc-filter-matrix.md, build 20348.5020)
     gives a different outcome for each under an AES-only filter. */
  assert.doesNotMatch(w, /when the KDC filter or the client does not allow them/);
  assert.match(w, /Under an AES-only KDC filter this site's lab \(Server 2022 build 20348\.5020\) saw KDC_ERR_ETYPE_NOSUPP when the set was the account's own msDS-SupportedEncryptionTypes, and an AES256 ticket when it was the DC's fallback for an account with no attribute\./);

  /* That upgrade is also why a ticket etype can be outside the set. */
  let up = withField(EX["4769-success"], "ServiceSupportedEncryptionTypes", "0x4 (RC4)");
  up = withField(up, "TicketEncryptionType", "0x12");
  assert.match(warningsOf(up), /not in the target's effective SupportedEncryptionTypes \(0x4\)\..*on Server 2022 build 20348\.5020, an AES-only KDC filter that upgraded the RC4 fallback of an account with no msDS-SupportedEncryptionTypes to an AES256 ticket/);
});

test("S4U2Proxy requests are called out", () => {
  const xml = withField(EX["4769-success"], "TicketOptions", "0x40820000");
  assert.match(warningsOf(xml), /S4U2Proxy \(constrained delegation\)/);
  assert.doesNotMatch(warningsOf(EX["4769-success"]), /S4U2Proxy/);
});

test("the S4U2Proxy note says only what the sources say, and ignores junk", () => {
  /* Bit 14 alone ([MS-SFU] 2.2.3). */
  let w = warningsOf(withField(EX["4769-success"], "TicketOptions", "0x40820000"));
  assert.match(w, /This is an S4U2Proxy \(constrained delegation\) request: KDC option cname-in-addl-tkt \(bit 14\) is set\./);
  /* Transited Services alone, described in Microsoft's words. */
  w = warningsOf(withField(EX["4769-success"], "TransmittedServices", "svc_app01@CORP.LOCAL"));
  assert.match(w, /Transited Services is populated, which indicates an S4U2Proxy \(constrained delegation\) request\. Microsoft's event documentation describes Transited Services as the list of SPNs that were requested if constrained Kerberos delegation was used\./);
  /* Nothing about who is impersonated or which service delegates. */
  for (const options of ["0x40820000", "0x40800000"]) {
    const both = withField(withField(EX["4769-success"], "TicketOptions", options), "TransmittedServices", "svc_app01@CORP.LOCAL");
    assert.doesNotMatch(warningsOf(both), /user being impersonated|names the delegating service/);
  }
  assert.doesNotMatch(dec.FIELD_SOURCES.TransmittedServices, /delegated through/);

  /* A CSV export leaves a stray quote after the empty marker. */
  const csv = [
    "Keywords,Date and Time,Source,Event ID,Task Category",
    "Audit Failure,11/9/2026 2:14:07 PM,Microsoft-Windows-Security-Auditing,4769,Kerberos Service Ticket Operations,\"A Kerberos service ticket was requested.",
    "",
    "Account Information:",
    "\tAccount Name:\t\talice@CORP.LOCAL",
    "\tAccount Domain:\t\tCORP.LOCAL",
    "",
    "Additional Information:",
    "\tTicket Options:\t\t0x40810000",
    "\tTicket Encryption Type:\t0xFFFFFFFF",
    "\tFailure Code:\t\t0xE",
    "\tTransited Services:\t-\"",
  ].join("\n");
  const p = dec.parseEvent(csv);
  assert.equal(p.fields.TransmittedServices, "-\"");
  assert.doesNotMatch(dec.generateWarnings(p).join("\n"), /S4U2Proxy/);
  for (const junk of ["-", " - ", "N/A", "\"\"", "--"]) {
    assert.doesNotMatch(warningsOf(withField(EX["4769-success"], "TransmittedServices", junk.replace(/"/g, "&quot;"))), /S4U2Proxy/, junk);
  }
});

test("a DES name in the client's list does not produce policy advice", () => {
  /* The built-in 4769 example lists DES-CBC-MD5 and DES-CBC-CRC. */
  assert.match(dec.parseEvent(EX["4769-success"]).fields.ClientAdvertizedEncryptionTypes, /DES-CBC-MD5 DES-CBC-CRC/);
  assert.deepEqual(dec.generateWarnings(dec.parseEvent(EX["4769-success"])), []);
  assert.doesNotMatch(warningsOf(EX["4769-success"]), /advertises DES|Remove DES/);
  /* DES actually used for a ticket is still reported. */
  assert.match(warningsOf(withField(EX["4769-success"], "TicketEncryptionType", "0x3")), /DES in Ticket Encryption Type/);
});

test("an RC4-only client is flagged from its etype list", () => {
  const xml = withField(EX["4769-success"], "ClientAdvertizedEncryptionTypes", "RC4-HMAC-NT RC4-HMAC-OLD");
  const w = warningsOf(xml);
  assert.match(w, /offered no AES etype/);
  /* Refused on enforcing builds, answered with an RC4 session key before (lab). */
  assert.match(w, /April 2026 cumulative update or later .* is refused when the target account's effective set is AES-only; in this site's lab, earlier builds answered it with an RC4 session key/);
});

test("no warning or note talks about the 2026 dates as upcoming", () => {
  const texts = [
    ...Object.values(dec.ENCRYPTION_TYPES).map((e) => e.note),
    ...Object.values(dec.FIELD_SOURCES),
    ...Object.values(dec.RESULT_CODES).map((r) => r.causes),
    warningsOf(withField(EX["4769-success"], "TicketEncryptionType", "0x17")),
  ].join("\n");
  assert.doesNotMatch(texts, /July 2026|will be (permanently )?disabled|Off by default July/i);
  assert.doesNotMatch(texts, /intersection of client offer/);
});

test("the etype summary separates ticket and session key inputs", () => {
  const groups = dec.buildPipeline(dec.parseEvent(EX["4769-success"]));
  assert.deepEqual(groups.map((g) => g.title), ["Ticket encryption", "Session key"]);
  const [ticket, session] = groups;
  assert.deepEqual(ticket.stages.map((s) => s.label), ["Target account effective set", "Target account keys", "KDC filter"]);
  assert.equal(ticket.stages.some((s) => /client/i.test(s.label)), false, "the client offer is not an input to the ticket etype");
  assert.match(ticket.stages[2].value, /Not recorded in the event/);
  assert.deepEqual(session.stages.map((s) => s.label), ["Client offer", "Target account effective set"]);
  assert.equal(groups.some((g) => g.stages.some((s) => /DC msDS|DDSET fallback/.test(s.label + s.value))), false);

  const tgt = dec.buildPipeline(dec.parseEvent(EX["4768-success"]));
  assert.deepEqual(tgt.map((g) => g.title), ["Ticket encryption", "Session key", "Pre-authentication"]);
  assert.deepEqual(dec.buildPipeline(dec.parseEvent(EX["4771-failure"])), []);
});

/* ------------------------------------------------------------------ */
/*  Share link                                                         */
/* ------------------------------------------------------------------ */

test("share hash round-trips, including non-ASCII", () => {
  const xml = EX["4769-success"].replace("Administrator", "Zoë");
  const hash = dec.buildShareHash(xml);
  assert.match(hash, /^#xml=[A-Za-z0-9_-]+$/);
  assert.equal(dec.readShareHash(hash), xml);
  assert.equal(dec.buildShareHash("   "), "");
  assert.equal(dec.readShareHash("#bit-flag-reference"), "");
  assert.equal(dec.readShareHash("#xml=%%%"), "");
});

/* ------------------------------------------------------------------ */
/*  Behaviour in a page                                                */
/* ------------------------------------------------------------------ */

function decodeIn(t, text) {
  t.$("#evdec-xml").value = text;
  t.$("#evdec-decode").click();
}

test("decoding never writes the event into the address bar", () => {
  const t = loadDecoder("https://example.test/security/event-decoder/?from=test");
  for (const btn of t.$$(".evdec-example-btn")) {
    btn.click();
    assert.equal(t.win.location.hash, "", btn.textContent);
    assert.equal(t.win.location.search, "?from=test");
    assert.equal(t.$("#evdec-results").style.display, "block");
  }
  assert.deepEqual(t.errors, []);
});

test("Copy Link is the only thing that builds a link, and says what it contains", () => {
  const t = loadDecoder();
  let copied = null;
  Object.defineProperty(t.win.navigator, "clipboard", { value: { writeText: (s) => { copied = s; return Promise.resolve(); } }, configurable: true });
  decodeIn(t, EX["4770-renew"]);
  t.$("#evdec-copy-link").click();
  assert.ok(copied.startsWith("https://example.test/security/event-decoder/#xml="));
  assert.equal(dec.readShareHash(copied.slice(copied.indexOf("#"))), EX["4770-renew"]);
  assert.equal(t.win.location.hash, "");
  assert.match(t.$("#evdec-privacy-note").textContent, /whole pasted event/);
  assert.equal(t.$("#evdec-xml").getAttribute("aria-describedby"), "evdec-privacy-note");
});

test("Copy Link with nothing pasted says so instead of copying a bare link", () => {
  const t = loadDecoder();
  let copied = null;
  Object.defineProperty(t.win.navigator, "clipboard", { value: { writeText: (s) => { copied = s; return Promise.resolve(); } }, configurable: true });
  t.$("#evdec-copy-link").click();
  assert.equal(copied, null);
  assert.equal(t.$("#evdec-error").style.display, "block");
  assert.match(t.$("#evdec-error").textContent, /Nothing to share yet/);
  assert.equal(t.$("#evdec-copy-link").textContent, "Copy Link", "no \"Copied\" confirmation");

  /* A result already on screen is left alone. */
  decodeIn(t, EX["4770-renew"]);
  t.$("#evdec-xml").value = "   ";
  t.$("#evdec-copy-link").click();
  assert.equal(copied, null);
  assert.equal(t.$("#evdec-results").style.display, "block");
});

test("the notice about several events is the first thing in the result", () => {
  const t = loadDecoder();
  decodeIn(t, "<Events>" + EX["4769-success"].replace("<EventID>4769", "<EventID>4624") + EX["4769-success"] + EX["4771-failure"] + "</Events>");
  assert.match(t.$("#evdec-header").textContent, /4769/);
  assert.equal(t.$("#evdec-warnings").style.display, "block");
  const first = t.$("#evdec-warnings .evdec-warning-item");
  assert.match(first.textContent, /holds 3 events\. Only one is decoded at a time: this is event 2 of 3, the first one that this decoder handles/);
  let copied = null;
  Object.defineProperty(t.win.navigator, "clipboard", { value: { writeText: (s) => { copied = s; return Promise.resolve(); } }, configurable: true });
  t.$("#evdec-copy-details").click();
  assert.match(copied, /^Note: The pasted text holds 3 events/m);

  /* A single event shows no such notice (this example has no warnings at all). */
  decodeIn(t, EX["4769-success"]);
  assert.equal(t.$("#evdec-warnings").style.display, "none");
  assert.deepEqual(t.errors, []);
});

test("a shared link decodes on load, and Clear removes it but keeps the query", () => {
  const url = "https://example.test/security/event-decoder/?a=1" + dec.buildShareHash(EX["4771-failure"]);
  const t = loadDecoder(url);
  assert.equal(t.$("#evdec-results").style.display, "block");
  assert.match(t.$("#evdec-header").textContent, /4771/);
  t.$("#evdec-clear").click();
  assert.equal(t.win.location.hash, "");
  assert.equal(t.win.location.search, "?a=1");
  assert.equal(t.$("#evdec-results").style.display, "none");
});

test("rendered result: labels, headers, status and focus", () => {
  const t = loadDecoder();
  decodeIn(t, EX["4768-failure"]);
  assert.match(t.$(".evdec-status").textContent, /Failure/);
  assert.doesNotMatch(t.$("#evdec-warnings").textContent, /pre-authentication/i);
  assert.equal(t.doc.activeElement, t.$("#evdec-results"), "focus moves to the result");
  assert.ok(t.$$("#evdec-fields thead th").every((th) => th.getAttribute("scope") === "col"));
  assert.ok(t.$$("#evdec-fields tbody th").every((th) => th.getAttribute("scope") === "row"));
  assert.ok(t.$("#evdec-fields caption"));
  assert.equal(t.$("#evdec-error").getAttribute("role"), "alert");
  assert.match(t.$("#evdec-ticket-options").textContent, /KDC Options Breakdown/);

  decodeIn(t, EX["4769-success"]);
  const text = t.$("#evdec-fields").textContent;
  assert.match(text, /Failure Code/);
  assert.match(text, /Service SupportedEncryptionTypes \(effective\)/);
  assert.match(text, /DES-CBC-CRC, DES-CBC-MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96/);
  assert.match(t.$("#evdec-pipeline").textContent, /How the KDC Chose These Etypes/);
});

test("missing or malformed fields are shown as such", () => {
  const t = loadDecoder();
  decodeIn(t, EX["4769-success"].replace('<Data Name="Status">0x0</Data>', ""));
  assert.match(t.$(".evdec-status").textContent, /Status missing/);
  assert.equal(t.$(".evdec-status").classList.contains("evdec-status--unknown"), true);

  decodeIn(t, withField(EX["4769-success"], "TicketOptions", "zz"));
  assert.match(t.$("#evdec-fields").textContent, /Unparseable/);
  assert.equal(t.$("#evdec-ticket-options").style.display, "none");
});

test("pasted markup is rendered as text, never as elements", () => {
  const t = loadDecoder();
  const evil = '&lt;img src=x onerror="window.__xss=1"&gt;&lt;script&gt;window.__xss=1&lt;/script&gt;';
  let xml = EX["4769-success"];
  for (const name of ["TargetUserName", "ServiceName", "TicketOptions", "Status", "IpAddress", "ClientAdvertizedEncryptionTypes", "ServiceSupportedEncryptionTypes"]) {
    xml = withField(xml, name, evil);
  }
  decodeIn(t, xml);
  assert.equal(t.$$("#event-decoder img, #event-decoder script").length, 0);
  assert.equal(t.win.__xss, undefined);
  t.$("#evdec-copy-details").click();
  assert.deepEqual(t.errors, []);
});

test("errors are shown and clear the previous result", () => {
  const t = loadDecoder();
  decodeIn(t, EX["4769-success"]);
  decodeIn(t, "not an event");
  assert.equal(t.$("#evdec-results").style.display, "none");
  assert.equal(t.$("#evdec-error").style.display, "block");
  assert.match(t.$("#evdec-error").textContent, /does not look like a Kerberos event/);
  decodeIn(t, "");
  assert.match(t.$("#evdec-error").textContent, /Paste an event/);
});

test("the text form decodes in the page too", () => {
  const t = loadDecoder();
  decodeIn(t, TEXT_4769);
  assert.match(t.$("#evdec-header").textContent, /parsed from text/);
  assert.match(t.$("#evdec-warnings").textContent, /AES-SK split/);
  assert.deepEqual(t.errors, []);
});

test("re-running init does not double-bind; other pages are left alone", () => {
  const t = loadDecoder();
  t.win.eval(read(DECODER_JS));
  let copies = 0;
  Object.defineProperty(t.win.navigator, "clipboard", { value: { writeText: () => { copies++; return Promise.resolve(); } }, configurable: true });
  decodeIn(t, EX["4770-renew"]);
  t.$("#evdec-copy-details").click();
  assert.equal(copies, 1);
  assert.equal(t.doc.body.classList.contains("event-decoder-page"), true);

  const { JSDOM } = require("jsdom");
  const other = new JSDOM("<!doctype html><body class='event-decoder-page'><p>other page</p></body>", { runScripts: "outside-only" });
  other.window.eval(read(DECODER_JS));
  assert.equal(other.window.document.body.classList.contains("event-decoder-page"), false);
});
