import fs from "node:fs/promises";
import { Presentation, PresentationFile } from "@oai/artifact-tool";
import { buildSlide01 } from "./slide-01.mjs";
import { buildSlide10 } from "./slide-10.mjs";
import { buildSlide13 } from "./slide-13.mjs";
import { buildSlide16 } from "./slide-16.mjs";
import { buildSlide26 } from "./slide-26.mjs";

const OUTPUT = "/Users/jaak/git/vibecheck/outputs/vibecheck-workshop-slides.pptx";
const RENDER_DIR = "/Users/jaak/git/vibecheck/.tmp/vibecheck-presentation/rendered";
const MONTAGE = "/Users/jaak/git/vibecheck/.tmp/vibecheck-presentation/montage.webp";

const W = 1280;
const H = 720;
const INK = "#000000";
const MUTED = "#5C6470";
const BLUE = "#3D8DFF";
const LIGHT_BLUE = "#D0EDFA";
const FONT = "Helvetica Neue";

function rich(value, { size = 24, bold = false, color = INK, italic = false, spaceAfter = 0 } = {}) {
  return {
    runs: [{
      run: value,
      textStyle: {
        fontSize: `${size}px`,
        typeface: FONT,
        color,
        bold,
        italic,
      },
    }],
    spaceAfter,
    paragraphStyle: { lineSpacingPercent: 100000 },
  };
}

function addText(slide, name, value, position, style = {}) {
  const box = slide.shapes.add({
    geometry: "textbox",
    name,
    position,
    fill: "none",
    line: { style: "solid", fill: "none", width: 0 },
  });
  box.text = value;
  box.text.style = {
    fontSize: style.fontSize ?? 22,
    typeface: FONT,
    color: style.color ?? INK,
    bold: style.bold ?? false,
    italic: style.italic ?? false,
    alignment: style.alignment ?? "left",
    verticalAlignment: style.verticalAlignment ?? "top",
    autoFit: style.autoFit ?? "shrinkText",
    wrap: "square",
    insets: style.insets ?? { top: 0, right: 0, bottom: 0, left: 0 },
  };
  return box;
}

function addTitle(slide, title, page) {
  addText(slide, `slide-${page}-title`, title,
    { left: 41.33, top: 36.12, width: 1197.33, height: 109.97 },
    { fontSize: 38.67, autoFit: "shrinkText" });
  addText(slide, `slide-${page}-number`, String(page),
    { left: 1184.18, top: 659.24, width: 54.48, height: 25.33 },
    { fontSize: 13.33, alignment: "right", verticalAlignment: "bottom", autoFit: "none" });
}

function addNotes(slide, lines, sources = []) {
  const noteLines = [...lines];
  if (sources.length) {
    noteLines.push("", "[Sources]", ...sources.map((source) => `- ${source}`), "[/Sources]");
  }
  slide.speakerNotes.textFrame.setText(noteLines);
  slide.speakerNotes.setVisible(true);
}

function addFlatRowsSlide(presentation, { page, title, rows, footerCallout, notes, sources = [], leftWidth = 500 }) {
  const slide = presentation.slides.add();
  slide.background.fill = "#FFFFFF";
  addTitle(slide, title, page);

  const top = 168;
  const rowHeight = 62;
  const gap = 10;
  rows.forEach((row, index) => {
    const y = top + index * (rowHeight + gap);
    addText(slide, `slide-${page}-row-${index + 1}-number`, String(index + 1).padStart(2, "0"),
      { left: 41.33, top: y, width: 64, height: rowHeight },
      { fontSize: 18, color: BLUE, bold: true, verticalAlignment: "middle", autoFit: "none" });
    addText(slide, `slide-${page}-row-${index + 1}-label`, row[0],
      { left: 120, top: y, width: leftWidth, height: rowHeight },
      { fontSize: 24, bold: true, verticalAlignment: "middle" });
    addText(slide, `slide-${page}-row-${index + 1}-detail`, row[1],
      { left: 650, top: y, width: 588.67, height: rowHeight },
      { fontSize: 20, color: MUTED, verticalAlignment: "middle" });
  });

  if (footerCallout) {
    addText(slide, `slide-${page}-callout`, footerCallout,
      { left: 650, top: 610, width: 540, height: 30 },
      { fontSize: 18, color: BLUE, bold: true, alignment: "right", verticalAlignment: "bottom" });
  }
  addNotes(slide, notes, sources);
  return slide;
}

const presentation = Presentation.create({ slideSize: { width: W, height: H } });

// 1 — Cover. Codex Grid layout 01.
{
  const slide = buildSlide01(presentation, {
    title: rich("15-MINUTE WORKSHOP", { size: 22, bold: true, color: BLUE }),
    title2: rich("Review vibe-coded apps.\nMake them safer.", { size: 72 }),
    title3: rich("A practical pre-launch review for websites, shops and internal tools", { size: 25 }),
  });
  addNotes(slide, [
    "Timing: 0:30",
    "Open with the promise: fast creation does not remove the need for evidence before publishing.",
    "Audience outcome: know what to check, what evidence to request and when to involve a specialist.",
  ]);
}

// 2 — Running example. Codex Grid layout 13.
{
  const slide = buildSlide13(presentation, {
    title: rich("A polished booking app can still fail four basic tests", { size: 38.67 }),
    body1: {
      titleGoesHere: rich("01  ACCESS BOUNDARY", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("Can one customer see another customer’s booking?", { size: 25 }),
    },
    body2: {
      titleGoesHere: rich("02  SECRET EXPOSURE", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("Is an API key visible in the browser?", { size: 25 }),
    },
    body3: {
      titleGoesHere: rich("03  COST ABUSE", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("Can someone trigger unlimited paid emails or AI calls?", { size: 25 }),
    },
    body4: {
      titleGoesHere: rich("04  RECOVERY", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("Can you recover if the database is deleted tomorrow?", { size: 25 }),
    },
    footer1: "2",
  });
  addNotes(slide, [
    "Timing: 1:15",
    "Running example: a salon booking app built in a weekend. It stores customer details, sends reminders, takes deposits and has an admin dashboard.",
    "Ask the audience whether they would trust it with customers before testing it.",
  ]);
}

// 3 — Five risk buckets. Codex Grid layout 10.
{
  const slide = buildSlide10(presentation, {
    title: rich("Most failures fall into five repeatable buckets", { size: 38.67 }),
    body1: rich("Ask plain-language questions first.", { size: 28, bold: true }),
    body2: {
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("Technical names can wait.", { size: 23, bold: true, spaceAfter: 700 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing2: rich("Start with what could go wrong for a customer—or for the business.", { size: 21, color: MUTED }),
    },
    label1: rich("Wrong person sees or changes data", { size: 21 }),
    label2: rich("A key is stolen or a bill explodes", { size: 21 }),
    label3: rich("The app behaves incorrectly", { size: 21 }),
    label4: rich("Failure goes unnoticed or unrecovered", { size: 21 }),
    label5: rich("Privacy, consumer or AI duties are missed", { size: 21 }),
    footer1: "3",
  });
  addNotes(slide, [
    "Timing: 1:30",
    "Translate the five buckets into questions: access, secrets/cost, correctness, reliability/recovery, and legal/responsible handling.",
    "Terms such as SQL injection or IDOR may be mentioned verbally, but they are not the organizing principle.",
  ]);
}

// 4 — Evidence ladder. Codex Grid layout 13.
{
  const slide = buildSlide13(presentation, {
    title: rich("A scanner is a clue—not a verdict", { size: 38.67 }),
    body1: {
      titleGoesHere: rich("01  STATIC SIGNAL", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("A suspicious pattern was found.", { size: 25 }),
    },
    body2: {
      titleGoesHere: rich("02  CODE + DATA FLOW", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("We traced where the data actually goes.", { size: 25 }),
    },
    body3: {
      titleGoesHere: rich("03  LIVE TEST", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("We tried the boundary with two users.", { size: 25 }),
    },
    body4: {
      titleGoesHere: rich("04  OPERATIONS", { size: 18, bold: true, color: BLUE, spaceAfter: 600 }),
      loremIpsumDolorSitAmetConsecteturAdipiscing: rich("We restored a backup and received an alert.", { size: 25 }),
    },
    footer1: "4",
  });
  addText(slide, "slide-4-callout", "NO_SIGNAL means “pattern not found”—not “safe.”",
    { left: 656.86, top: 611, width: 581.33, height: 35 },
    { fontSize: 20, bold: true, color: BLUE, alignment: "right", verticalAlignment: "bottom" });
  addNotes(slide, [
    "Timing: 1:30",
    "The evidence becomes stronger as we move from a static pattern to code tracing, a live test and operational proof.",
    "Important: clearing one scanner warning clears that signal only. It does not prove the whole control passes.",
  ]);
}

// 5 — Six-step review loop.
addFlatRowsSlide(presentation, {
  page: 5,
  title: "Review in six repeatable steps",
  rows: [
    ["Scope", "Describe the application in five sentences"],
    ["Inventory", "List users, sensitive data, payments, AI and providers"],
    ["Map", "Trace browser → backend → database or provider"],
    ["Scan", "Run automated checks and keep their raw evidence"],
    ["Test live", "Try the important journeys and access boundaries"],
    ["Fix + retest", "Record evidence, assign owners and verify again"],
  ],
  footerCallout: "Pass · Partial · Fail · Not tested · N/A + reason",
  notes: [
    "Timing: 2:00",
    "Walk through the loop quickly. Stress that a review is repeatable and evidence-driven.",
    "Unresolved manual checks remain Not tested. Absence-based items need reproducible repository, configuration or command evidence—not invented file-and-line citations.",
  ],
});

// 6 — Managed building blocks. Codex Grid layout 16.
{
  const item = (title, detail) => ({
    titleHere: rich(title, { size: 18, bold: true, color: BLUE, spaceAfter: 500 }),
    loremIpsumDolorSitAmetConsecteturAdipiscing: rich(detail, { size: 17.5, color: INK }),
  });
  const slide = buildSlide16(presentation, {
    title: rich("Safer apps use boring, managed building blocks", { size: 38.67 }),
    body1: item("AUTHENTICATION", "Use an established provider."),
    body2: item("PERMISSIONS", "Enforce them server-side or in the database."),
    body3: item("SECRETS", "Keep keys out of browsers and Git history."),
    body4: item("INPUT + OUTPUT", "Validate input; use safe APIs; encode output."),
    body5: item("PAYMENTS", "Use hosted checkout; verify webhook signatures."),
    body6: item("LIMITS", "Add quotas, timeouts and spending alerts."),
    body7: item("RECOVERY", "Back up, monitor and name an alert owner."),
    body8: item("DEPENDENCIES", "Pin, scan and update deliberately."),
    footer1: "6",
  });
  addNotes(slide, [
    "Timing: 2:00",
    "Theme: build the business-specific experience with AI, but rely on mature services for high-risk infrastructure.",
    "Hiding a button is not permission enforcement. A browser-visible key is not a secret.",
  ]);
}

// 7 — Regulation and standards trigger map.
addFlatRowsSlide(presentation, {
  page: 7,
  title: "Rules follow the feature—not the coding tool",
  leftWidth: 500,
  rows: [
    ["Identifiable people data", "GDPR: purpose, minimisation, retention, rights and security"],
    ["EU consumer sales", "Trader, price, payment, delivery, complaint and withdrawal information"],
    ["E-commerce services", "Accessibility scope and national implementation"],
    ["AI with people or content", "Disclosure, literacy, prohibited-use and high-risk screening"],
    ["Card payments", "Hosted provider plus applicable PCI DSS responsibilities"],
    ["High-impact decisions", "Specialist legal and security review before launch"],
  ],
  notes: [
    "Timing: 2:00",
    "Keep this high-level. The trigger is what the application does and whose data or decisions it affects.",
    "GDPR requires data protection by design/default. EU online-selling guidance lists advance information duties. The European Accessibility Act covers e-commerce among other services.",
    "As checked on 11 August 2026, the AI Act is generally applicable, with specific transition dates for some high-risk systems. Verify the current scope and national implementation for the use case.",
    "Use OWASP Top 10 for awareness, OWASP ASVS 5.0 for testable security requirements and WCAG 2.2 as a practical accessibility target.",
    "This slide is general education, not legal advice.",
  ],
  sources: [
    "https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/obligations/what-does-data-protection-design-and-default-mean_en",
    "https://europa.eu/youreurope/business/selling-in-eu/selling-goods-services/ecommerce-distance-selling/index_en.htm",
    "https://commission.europa.eu/strategy-and-policy/policies/justice-and-fundamental-rights/disability/european-accessibility-act-eaa_en",
    "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
    "https://owasp.org/Top10/",
    "https://owasp.org/www-project-application-security-verification-standard/",
    "https://www.w3.org/TR/WCAG22/",
  ],
});

// 8 — Ten-question launch check.
{
  const slide = presentation.slides.add();
  slide.background.fill = "#FFFFFF";
  addTitle(slide, "The ten-question launch check", 8);
  const questions = [
    "Can someone explain the app and data flow in five sentences?",
    "Does the business own the domain, repository, database and accounts?",
    "Were secrets checked in current code and Git history?",
    "Was access tested with two different user accounts?",
    "Are permissions enforced by the backend or database?",
    "Are inputs validated, queries safe and uploads limited?",
    "Are payments and webhooks signed and duplicate-safe?",
    "Are expensive actions authenticated, limited and budget-capped?",
    "Were the main journey, alerts and backup restore actually tested?",
    "Is there evidence for applicable privacy, consumer, accessibility and AI duties?",
  ];
  questions.forEach((question, index) => {
    const column = index < 5 ? 0 : 1;
    const row = index % 5;
    const x = column === 0 ? 41.33 : 656.86;
    const y = 160 + row * 91;
    addText(slide, `slide-8-question-${index + 1}-number`, String(index + 1).padStart(2, "0"),
      { left: x, top: y, width: 54, height: 72 },
      { fontSize: 17, color: BLUE, bold: true, verticalAlignment: "top", autoFit: "none" });
    addText(slide, `slide-8-question-${index + 1}`, question,
      { left: x + 64, top: y, width: 505, height: 72 },
      { fontSize: 19.5, verticalAlignment: "top" });
  });
  addText(slide, "slide-8-callout", "Critical or High risk is not a Pass without evidence.",
    { left: 656.86, top: 616, width: 530, height: 32 },
    { fontSize: 18, color: BLUE, bold: true, alignment: "right", verticalAlignment: "bottom" });
  addNotes(slide, [
    "Timing: 3:00",
    "Invite the audience to photograph this slide or use it as the take-home handout.",
    "A checklist reduces risk; it does not certify an application as secure.",
    "For each answer, request evidence: a test result, configuration, screenshot, log, restore record or named owner and due date.",
  ]);
}

// 9 — Close. Codex Grid layout 26.
{
  const slide = buildSlide26(presentation, {
    title: rich("TODAY", { size: 22, bold: true, color: BLUE }),
    title2: rich("Evidence beats\nconfidence.", { size: 72 }),
    title3: {
      loremIpsumDetails: rich("Create two test accounts", { size: 23 }),
      loremIpsumDetails2: rich("Scan secrets + dependencies", { size: 23 }),
      loremIpsumDetails3: rich("Assign every open item", { size: 23 }),
    },
  });
  addText(slide, "slide-9-final-question", "Do not ask, “Does it look finished?”\nAsk, “What evidence says it behaves safely?”",
    { left: 656, top: 500, width: 540, height: 130 },
    { fontSize: 24, italic: true, color: MUTED, alignment: "right", verticalAlignment: "bottom" });
  addNotes(slide, [
    "Timing: 1:15",
    "Close with three actions: test the access boundary with two accounts; run dedicated secret and dependency scanners; give every unanswered item an owner and due date.",
    "Final message: vibe coding makes software faster to create—not safer to publish. A good review replaces confidence with evidence.",
  ]);
}

// 10 — Optional backup: toolbox. Codex Grid layout 16.
{
  const item = (title, detail) => ({
    titleHere: rich(title, { size: 18, bold: true, color: BLUE, spaceAfter: 500 }),
    loremIpsumDolorSitAmetConsecteturAdipiscing: rich(detail, { size: 17, color: INK }),
  });
  const slide = buildSlide16(presentation, {
    title: rich("Optional: a mostly free starter toolbox", { size: 38.67 }),
    body1: item("GITLEAKS / TRUFFLEHOG", "Secrets in files and Git history"),
    body2: item("SEMGREP CE", "Suspicious code patterns"),
    body3: item("OSV-SCANNER", "Known dependency vulnerabilities"),
    body4: item("TRIVY", "Dependencies, containers and IaC"),
    body5: item("OWASP ZAP", "Running web application checks"),
    body6: item("PLAYWRIGHT", "Repeatable user journeys"),
    body7: item("LIGHTHOUSE", "Accessibility and quality signals"),
    body8: item("AXE-CORE", "Automated accessibility checks"),
    footer1: "10",
  });
  addNotes(slide, [
    "Optional backup slide; not part of the 15-minute main sequence.",
    "Use tools as evidence generators, not as certification. Start with secrets and dependency scanning, then add code, live-app and accessibility checks.",
    "Some tools also offer paid hosted products; the named community/open-source components are the intended starting point.",
  ], [
    "https://github.com/gitleaks/gitleaks",
    "https://github.com/trufflesecurity/trufflehog",
    "https://semgrep.dev/products/community-edition/",
    "https://github.com/google/osv-scanner",
    "https://trivy.dev/",
    "https://www.zaproxy.org/",
    "https://playwright.dev/",
    "https://developer.chrome.com/docs/lighthouse/",
    "https://github.com/dequelabs/axe-core",
  ]);
}

await fs.mkdir(RENDER_DIR, { recursive: true });
for (const [index, slide] of presentation.slides.items.entries()) {
  const stem = `slide-${String(index + 1).padStart(2, "0")}`;
  const png = await presentation.export({ slide, format: "png", scale: 1 });
  await fs.writeFile(`${RENDER_DIR}/${stem}.png`, new Uint8Array(await png.arrayBuffer()));
  const layout = await slide.export({ format: "layout" });
  await fs.writeFile(`${RENDER_DIR}/${stem}.layout.json`, await layout.text());
}

const montage = await presentation.export({ format: "webp", montage: true, scale: 1 });
await fs.writeFile(MONTAGE, new Uint8Array(await montage.arrayBuffer()));

const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save(OUTPUT);

const inspect = await presentation.inspect({
  kind: "slide,textbox,shape,table,notes",
  maxChars: 50000,
});
await fs.writeFile("/Users/jaak/git/vibecheck/.tmp/vibecheck-presentation/deck-inspect.ndjson", inspect.ndjson);

console.log(OUTPUT);
