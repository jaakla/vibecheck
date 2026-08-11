export function safeParse(s) {
  try {
    return JSON.parse(s);
  } catch (e) {}
  return null;
}
