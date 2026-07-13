// ═══════════════════════════════════════════════════════════════════════
//  OWASP TIET Recruitment 2026 — Google Apps Script Backend
//  GitHub repo:  sy-recruitment
//
//  SETUP STEPS:
//  1. Go to https://script.google.com → New project.
//  2. Paste this entire file (replace the default code).
//  3. Fill in SHEET_ID and FOLDER_ID below.
//  4. Click Deploy → New deployment → Web app.
//       Execute as:     Me
//       Who has access: Anyone
//  5. Copy the Web App URL.
//  6. Paste it into index.html where it says APPS_SCRIPT_URL.
// ═══════════════════════════════════════════════════════════════════════

// ── CONFIG — fill these in ────────────────────────────────────────────
const SHEET_ID  = 'YOUR_GOOGLE_SHEET_ID_HERE';
// From: https://docs.google.com/spreadsheets/d/ <<<THIS_PART>>> /edit

const FOLDER_ID = 'YOUR_GOOGLE_DRIVE_FOLDER_ID_HERE';
// From: https://drive.google.com/drive/folders/ <<<THIS_PART>>>
// ─────────────────────────────────────────────────────────────────────

// ── Sheet column headers ──────────────────────────────────────────────
const HEADERS = [
  // Personal
  'Timestamp', 'Email', 'Name', 'Roll No.', 'Mobile No.', 'Branch', 'Domain',

  // Cybersecurity
  'CS · Platforms & Tools',
  'CS · Project / Lab Description',
  'CS · GitHub ID',
  'CS · Repository Link',
  'CS · CTF Challenge/Exploit',
  'CS · CTF Count',
  'CS · Website Security Check (3 things)',
  'CS · Currently Learning / Plan',

  // Technical
  'Tech · Comfortable Technology & Builds',
  'Tech · Proud Project Description',
  'Tech · GitHub ID',
  'Tech · Repository Link',
  'Tech · GitHub Contribution Confidence',

  // Design / Media
  'DM · Design Software & Work Type',
  'DM · Portfolio / Project & Role',
  'DM · Figma Link',
  'DM · 24h Workshop Promotion Approach',

  // Marketing / Outreach
  'MO · Outreach / Sponsor Experience',
  'MO · Campaign / Initiative & Outcome',
  'MO · Low-Registration Strategy (3 days)',

  // Common
  'Societies & Roles',
  'Why Join OWASP',
  'About Yourself (not on resume)',
  'OWASP Goal (1 year)',

  // Resume
  'Resume',   // ← Google Drive link stored here
];

// ── Security: HTML-escape a string for safe use in email HTML ─────────
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─────────────────────────────────────────────────────────────────────
function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);

    // ══ SERVER-SIDE VALIDATION (M1 + M2 security fixes) ══════════════
    // These checks mirror client-side validation and cannot be bypassed.

    // Email: must end in @thapar.edu
    if (!data.email || !/^[^\s@]+@thapar\.edu$/i.test(String(data.email).trim())) {
      return jsonResponse({ success: false, error: 'Email must end in @thapar.edu.' });
    }

    // Name: required, at least 2 characters
    if (!data.name || String(data.name).trim().length < 2) {
      return jsonResponse({ success: false, error: 'Full name is required.' });
    }

    // Roll number: 9–12 digits
    if (!data.roll || !/^\d{9,12}$/.test(String(data.roll).trim())) {
      return jsonResponse({ success: false, error: 'Roll number must be 9–12 digits.' });
    }

    // Mobile: exactly 10 digits
    if (!data.mobile || !/^\d{10}$/.test(String(data.mobile).trim())) {
      return jsonResponse({ success: false, error: 'Mobile must be exactly 10 digits.' });
    }

    // Domain: must be one of the accepted values
    const VALID_DOMAINS = ['cybersecurity', 'technical', 'media', 'designing', 'marketing', 'outreach'];
    if (!data.domain || !VALID_DOMAINS.includes(String(data.domain))) {
      return jsonResponse({ success: false, error: 'Invalid domain selection.' });
    }

    // File extension: only PDF, DOC, DOCX (M2 fix)
    const ALLOWED_EXTS = ['pdf', 'doc', 'docx'];
    const ext = String(data.resumeExt || '').toLowerCase().replace(/[^a-z]/g, '');
    if (!ALLOWED_EXTS.includes(ext)) {
      return jsonResponse({ success: false, error: 'Only PDF, DOC, DOCX files are allowed.' });
    }

    // File size: Base64 of 10 MB ≈ 13.6 MB string; reject anything bigger
    if (!data.resumeBase64 || data.resumeBase64.length > 14_000_000) {
      return jsonResponse({ success: false, error: 'File missing or exceeds 10 MB limit.' });
    }
    // ══════════════════════════════════════════════════════════════════

    // 1. Upload resume to Google Drive ─────────────────────────────────
    const folder = DriveApp.getFolderById(FOLDER_ID);

    // Sanitize name for use as filename (strip illegal filesystem chars)
    const safeName = String(data.name)
                       .replace(/[\/\\:*?"<>|]/g, '')
                       .trim()
                       .substring(0, 100); // cap at 100 chars

    const fileName = safeName + '.' + ext;

    // Use a whitelisted MIME type — ignore whatever the client claims (M2 fix)
    const MIME_MAP = {
      pdf:  'application/pdf',
      doc:  'application/msword',
      docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    };
    const mimeType = MIME_MAP[ext];

    const fileBytes = Utilities.base64Decode(data.resumeBase64);
    const blob      = Utilities.newBlob(fileBytes, mimeType, fileName);

    const driveFile = folder.createFile(blob);
    driveFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
    const resumeUrl = driveFile.getUrl();

    // 2. Open sheet; add styled headers on first run ────────────────────
    const ss    = SpreadsheetApp.openById(SHEET_ID);
    const sheet = ss.getSheets()[0];

    if (sheet.getLastRow() === 0) {
      sheet.appendRow(HEADERS);
      const headerRange = sheet.getRange(1, 1, 1, HEADERS.length);
      headerRange
        .setFontWeight('bold')
        .setBackground('#5b4bdc')
        .setFontColor('#ffffff')
        .setWrap(true);
      sheet.setFrozenRows(1);
      sheet.setRowHeight(1, 60);
    }

    // 3. Build data row ─────────────────────────────────────────────────
    const row = [
      // Personal
      new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
      data.email  || '',
      data.name   || '',
      data.roll   || '',
      data.mobile || '',
      data.branch || '',
      data.domain || '',

      // Cybersecurity
      data.csStack        || '',
      data.csProject      || '',
      data.csGithub       || '',
      data.csRepo         || '',
      data.csCtf          || '',
      data.csCtfCount     || '',
      data.csWebsiteCheck || '',
      data.csLearning     || '',

      // Technical
      data.techStack      || '',
      data.techProject    || '',
      data.techGithub     || '',
      data.techRepo       || '',
      data.techConfidence || '',

      // Design / Media
      data.dmTools     || '',
      data.dmPortfolio || '',
      data.dmFigma     || '',
      data.dmWorkshop  || '',

      // Marketing / Outreach
      data.moOutreach || '',
      data.moCampaign || '',
      data.moScenario || '',

      // Common
      data.societies || '',
      data.whyOwasp  || '',
      data.extraInfo || '',
      data.owaspGoal || '',

      // Resume — clickable Drive link
      resumeUrl,
    ];

    sheet.appendRow(row);

    // Make Resume column a clickable hyperlink
    const lastRow   = sheet.getLastRow();
    const resumeCol = HEADERS.indexOf('Resume') + 1;
    sheet.getRange(lastRow, resumeCol)
      .setFormula(`=HYPERLINK("${resumeUrl}","📄 ${safeName}")`);

    // Auto-resize for readability
    sheet.autoResizeColumns(1, HEADERS.length);

    // 4. Email a copy of the response to the applicant (only if they opted in)
    if (data.sendCopy === true && data.email) {
      try {
        const DOMAIN_LABELS = {
          cybersecurity: 'Cybersecurity', technical: 'Technical',
          media: 'Media', designing: 'Designing',
          marketing: 'Marketing', outreach: 'Outreach',
        };
        const domainLabel = DOMAIN_LABELS[data.domain] || data.domain || '';

        // H2 FIX: strip newlines from name before using in email subject
        //         (prevents email header injection)
        const subjectSafeName = String(data.name || 'Applicant')
                                  .replace(/[\r\n\t]/g, ' ')
                                  .trim()
                                  .substring(0, 100);

        // H2 FIX: HTML-escape name and all user values before inserting into
        //         email HTML body (prevents HTML injection in email client)
        const eName = escapeHtml(subjectSafeName);

        const pairs = [
          ['Email',   data.email],
          ['Name',    data.name],
          ['Roll No.', data.roll],
          ['Mobile',  data.mobile],
          ['Branch',  data.branch],
          ['Domain',  domainLabel],
          // Domain-specific answers
          ...(data.domain === 'cybersecurity' ? [
            ['CS: Platforms & Tools',  data.csStack],
            ['CS: Project / Lab',       data.csProject],
            ['CS: GitHub',              data.csGithub],
            ['CS: CTF Challenge',       data.csCtf],
            ['CS: CTF Count',           data.csCtfCount],
            ['CS: Website Check (3)',   data.csWebsiteCheck],
            ['CS: Currently Learning',  data.csLearning],
          ] : []),
          ...(data.domain === 'technical' ? [
            ['Tech: Stack & Builds',   data.techStack],
            ['Tech: Proud Project',    data.techProject],
            ['Tech: GitHub',           data.techGithub],
            ['Tech: Confidence',       data.techConfidence],
          ] : []),
          ...(['media','designing'].includes(data.domain) ? [
            ['DM: Tools & Work Type',  data.dmTools],
            ['DM: Portfolio & Role',   data.dmPortfolio],
            ['DM: Figma Link',         data.dmFigma],
            ['DM: Workshop Approach',  data.dmWorkshop],
          ] : []),
          ...(['marketing','outreach'].includes(data.domain) ? [
            ['MO: Outreach / Sponsors', data.moOutreach],
            ['MO: Campaign & Outcome',  data.moCampaign],
            ['MO: 3-Day Strategy',      data.moScenario],
          ] : []),
          ['Societies & Roles',  data.societies],
          ['Why OWASP',          data.whyOwasp],
          ['About Yourself',     data.extraInfo],
          ['OWASP Goal (1 yr)',  data.owaspGoal],
          ['Resume',             `${fileName} — ${resumeUrl}`],
        ].filter(([, v]) => v);

        // Build table rows — spacious layout, alternating row bg, all values HTML-escaped
        const tableRows = pairs.map(([k, v], i) => {
          const rowBg = i % 2 === 0 ? '#16161f' : '#111118';
          return `<tr style="background:${rowBg};">` +
            `<td style="padding:13px 18px;color:#7c6bff;font-weight:600;font-size:12px;` +
            `white-space:nowrap;vertical-align:top;width:38%;` +
            `border-bottom:1px solid #1e1e2e;text-transform:uppercase;letter-spacing:0.5px;">${escapeHtml(k)}</td>` +
            `<td style="padding:13px 18px;color:#ddddf0;font-size:13px;line-height:1.7;` +
            `word-break:break-word;vertical-align:top;` +
            `border-bottom:1px solid #1e1e2e;">${escapeHtml(v)}</td>` +
            `</tr>`;
        }).join('');

        const htmlBody = `
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
<body style="margin:0;padding:0;background:#0d0d14;font-family:Arial,Helvetica,sans-serif;">
<div style="max-width:640px;margin:0 auto;background:#0d0d14;">

  <!-- LOGO BANNER -->
  <div style="background:#111118;border-bottom:2px solid #5b4bdc;padding:28px 40px;text-align:center;">
    <img src="https://sy-recruitment.netlify.app/logo.png"
         alt="OWASP TIET Student Chapter" width="220"
         style="display:block;margin:0 auto;
                filter:drop-shadow(0 0 10px rgba(124,107,255,0.7)) drop-shadow(0 0 24px rgba(91,75,220,0.45));" />
  </div>

  <!-- HERO -->
  <div style="background:linear-gradient(135deg,#1a1530 0%,#111118 100%);
              padding:36px 40px 28px;text-align:center;border-bottom:1px solid #252535;">
    <div style="display:inline-block;width:56px;height:56px;line-height:56px;font-size:26px;
                border-radius:50%;background:linear-gradient(135deg,#5b4bdc,#7c6bff);
                color:#fff;margin-bottom:16px;">✓</div>
    <h1 style="color:#ffffff;font-size:22px;font-weight:700;margin:0 0 8px;letter-spacing:-0.3px;">
      Application Submitted!
    </h1>
    <p style="color:#888;font-size:13px;margin:0;">
      OWASP TIET Student Chapter &middot; Recruitment 2026
    </p>
  </div>

  <!-- BODY -->
  <div style="padding:36px 40px;">

    <!-- Greeting -->
    <p style="color:#b8b8d0;font-size:15px;line-height:1.9;margin:0 0 32px;">
      Hi <strong style="color:#ffffff;">${eName}</strong>,<br/>
      Thank you for applying to the OWASP TIET Student Chapter!
      Below is a copy of your submitted application for your records.
      We&rsquo;ll review it carefully and reach out before the deadline.
    </p>

    <!-- Section label -->
    <p style="color:#5b4bdc;font-size:11px;font-weight:700;letter-spacing:1.4px;
              text-transform:uppercase;margin:0 0 14px;padding-bottom:10px;
              border-bottom:1px solid #2a2a40;">
      Your Submitted Responses
    </p>

    <!-- Response table -->
    <table style="width:100%;border-collapse:collapse;margin-bottom:36px;">
      ${tableRows}
    </table>

    <!-- Divider -->
    <hr style="border:none;border-top:1px solid #252535;margin:0 0 28px;"/>

    <!-- Sign-off -->
    <p style="color:#7c6bff;font-size:15px;font-weight:600;text-align:center;margin:0 0 10px;">
      Stay sharp. Stay secure. 🔐
    </p>
    <p style="color:#555;font-size:12px;text-align:center;margin:0;">
      This is an automated confirmation email — please do not reply.
    </p>

  </div>

  <!-- FOOTER BAR -->
  <div style="background:#111118;border-top:1px solid #252535;padding:18px 40px;text-align:center;">
    <p style="color:#444;font-size:11px;margin:0;">
      &copy; 2026 OWASP TIET Student Chapter &middot; Thapar Institute of Engineering &amp; Technology
    </p>
  </div>

</div>
</body>
</html>`;

        // Plain-text fallback for email clients that don't render HTML
        const plainText = pairs.map(([k, v]) => `${k}: ${v}`).join('\n');

        MailApp.sendEmail({
          to:       String(data.email),
          subject:  `OWASP TIET Recruitment 2026 — Application received (${subjectSafeName})`,
          body:     plainText,
          htmlBody: htmlBody,
        });

      } catch (mailErr) {
        // Non-fatal: log but do not fail the submission
        Logger.log('Email send failed: ' + mailErr.message);
      }
    }

    // 5. Return success ─────────────────────────────────────────────────
    return jsonResponse({ success: true, resumeUrl, fileName });

  } catch (err) {
    Logger.log('ERROR: ' + err.message + '\n' + err.stack);
    return jsonResponse({ success: false, error: err.message });
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────
function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// Health-check GET — remove this after confirming deployment works
function doGet() {
  return jsonResponse({ status: 'OWASP TIET Recruitment backend is live ✅' });
}
