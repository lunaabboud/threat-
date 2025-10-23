Threat Intelligence Pipeline
A React-based single-page application for analyzing security logs using an LLM-powered threat intelligence pipeline. The application provides detailed threat assessments, including attack narratives, MITRE ATT&CK mappings, and actionable recommendations.
Features

Input security logs and analyze them with a mock LLM or real LLM (OpenAI GPT-4 or Anthropic Claude).
Extracts Indicators of Compromise (IOCs) like IPs, domains, users, ports, files, and emails.
Provides quick classification of threats (e.g., brute-force, phishing, malware, DDoS).
Responsive UI with Tailwind CSS and Lucide icons.

Prerequisites

Node.js (v16 or higher)
npm or yarn
GitHub account for hosting

Setup Instructions

Clone the Repository
git clone https://github.com/your-username/threat-intel-pipeline.git
cd threat-intel-pipeline


Install Dependencies
npm install


Run Locally
npm run dev

Open http://localhost:5173/threat-intel-pipeline in your browser.


Deploy to GitHub Pages

Install gh-pagesAlready included in package.json. Ensure it's installed with npm install.

Update vite.config.jsEnsure the base property in vite.config.js matches your repository name:
base: '/threat-intel-pipeline/'


Deploy
npm run deploy


Configure GitHub Pages

Go to your repository on GitHub.
Navigate to Settings > Pages.
Set the source to Deploy from a branch and select the gh-pages branch.
Save and wait for the deployment to complete.


Access the AppThe app will be available at https://your-username.github.io/threat-intel-pipeline/.


Notes

The app uses a mock LLM by default for demo purposes. To use a real LLM, obtain an API key from OpenAI or Anthropic and configure it in the app.
The app uses Tailwind CSS via CDN for simplicity. For production, consider installing Tailwind CSS locally.
Lucide icons are used for UI elements and require the lucide-react package.

License
MIT License
