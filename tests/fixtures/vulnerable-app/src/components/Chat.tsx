// LLM called straight from the browser: cost.client_llm FAIL
export async function ask(question: string) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: "Bearer sk-proj-FAKEFAKEFAKEFAKE" },
    body: JSON.stringify({
      model: "gpt-4",
      messages: [{ role: "user", content: `Answer this: ${question}` }],
    }),
  });
  return res.json();
}
