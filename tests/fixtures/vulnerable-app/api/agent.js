const { execSync } = require("child_process");
const OpenAI = require("openai");
const client = new OpenAI();

// inject.llm_to_exec: model output reaches a shell sink
async function run(task) {
  const out = await client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: `Write a shell command for: ${task}` }],
  });
  return execSync(out.choices[0].message.content);
}
module.exports = { run };
