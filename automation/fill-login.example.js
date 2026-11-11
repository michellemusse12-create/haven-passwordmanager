import { chromium } from "playwright";

// Run only for a site and account you are authorized to access.
// Provide LOGIN_URL, LOGIN_USERNAME, and LOGIN_PASSWORD through your shell environment.
const { LOGIN_URL, LOGIN_USERNAME, LOGIN_PASSWORD } = process.env;
if (!LOGIN_URL || !LOGIN_USERNAME || !LOGIN_PASSWORD) {
  throw new Error("Set LOGIN_URL, LOGIN_USERNAME, and LOGIN_PASSWORD before running.");
}

const browser = await chromium.launch({ headless: false });
try {
  const page = await browser.newPage();
  await page.goto(LOGIN_URL, { waitUntil: "domcontentloaded" });
  await page.locator('input[autocomplete="username"], input[type="email"]').first().fill(LOGIN_USERNAME);
  await page.locator('input[autocomplete="current-password"], input[type="password"]').first().fill(LOGIN_PASSWORD);
  // Inspect the site's form and selector before enabling a submit action.
} finally {
  await browser.close();
}
