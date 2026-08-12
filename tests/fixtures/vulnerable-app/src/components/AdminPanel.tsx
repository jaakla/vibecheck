import { createClient } from "@supabase/supabase-js";

// service_role key in a client component: secrets.service_role WARN
const supabase = createClient(
  "https://example.supabase.co",
  "service_role.FAKEFAKEFAKE"
);

export function AdminPanel({ user }: { user: any }) {
  const isAdmin = user.role === "admin";   // authz.client_admin
  if (!isAdmin) return null;
  return <div dangerouslySetInnerHTML={{ __html: user.bio }} />;  // inject.xss
}
