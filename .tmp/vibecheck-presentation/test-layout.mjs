import fs from "node:fs/promises";
import { Presentation, PresentationFile } from "@oai/artifact-tool";
import { buildSlide01 } from "./slide-01.mjs";

const presentation = Presentation.create({ slideSize: { width: 1280, height: 720 } });
const slide = buildSlide01(presentation, {
  title: "WORKSHOP",
  title2: "How to review a\nvibe-coded app",
  title3: "A practical pre-launch review",
});
const png = await presentation.export({ slide, format: "png", scale: 1 });
await fs.writeFile("/Users/jaak/git/vibecheck/.tmp/vibecheck-presentation/test-layout.png", new Uint8Array(await png.arrayBuffer()));
const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save("/Users/jaak/git/vibecheck/.tmp/vibecheck-presentation/test-layout.pptx");
