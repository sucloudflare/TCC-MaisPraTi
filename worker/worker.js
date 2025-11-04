// worker/worker.js
import { chromium } from "playwright";
import fs from "fs";
import path from "path";
import axios from "axios";

const BACKEND_URL = process.env.BACKEND_URL || "http://backend:8080";
const TARGET_URL = process.env.TARGET_URL || process.argv[2] || "http://juice_lab:3000";

const REPORTS_DIR = "/data/reports";
const SCREENSHOTS_DIR = "/data/screenshots";

if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });
if (!fs.existsSync(SCREENSHOTS_DIR)) fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });

async function runJob(job) {
  const jobId = job?.id || Date.now();
  const target = job?.targetUrl || TARGET_URL;

  let browser;
  try {
    browser = await chromium.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
    const page = await browser.newPage();

    await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 });
    const title = await page.title();
    const screenshotPath = path.join(SCREENSHOTS_DIR, `job-${jobId}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });

    const report = {
      jobId,
      url: target,
      title,
      screenshot: `/reports/screenshots/job-${jobId}.png`,
      timestamp: new Date().toISOString(),
      meta: {
        viewport: await page.viewportSize()
      }
    };

    // salvar relatório local
    const reportPath = path.join(REPORTS_DIR, `job-${jobId}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

    // opcional: notificar backend que job terminou (se backend expor endpoint)
    try {
      await axios.post(`${BACKEND_URL}/api/jobs/${jobId}/result`, report, { timeout: 5000 });
    } catch (err) {
      // backend not available or endpoint not present — ok, apenas logamos
      console.warn("Não foi possível notificar o backend:", err.message);
    }

    console.log(`Job ${jobId} finalizado: ${reportPath}`);
  } catch (err) {
    console.error("Erro no worker:", err.message);
  } finally {
    if (browser) await browser.close();
  }
}

// Se executar diretamente, roda um job simples
if (import.meta.url === `file://${process.argv[1]}`) {
  const argUrl = process.argv[2] || TARGET_URL;
  const argJob = process.argv[3] || Date.now();
  runJob({ id: argJob, targetUrl: argUrl });
}

export default runJob;
