# MA Tier 0 Risk Assessment Assistant Prototype

This is a Streamlit prototype for generating draft MA Tier 0 website risk assessment rows aligned to the SOP and Excel checklist.

## What it does in Version 1

- Single URL assessment
- Batch assessment from CSV/XLSX
- Draft Excel export
- URL/domain normalization
- DNS resolution
- SSL certificate validity check
- robots.txt check
- page title/meta description extraction
- basic tracker detection
- RDAP lookup for registrar/country where available
- VirusTotal URL check when an API key is provided
- Manual review links for tools that should remain analyst verified

## Important security note

Do not paste your real VirusTotal API key into shared code or into ChatGPT. Store it locally in `.env` or use Streamlit secrets.

## Setup on Windows PowerShell

1. Unzip this folder.
2. Open PowerShell in the project folder.
3. Create a virtual environment:

```powershell
python -m venv .venv
```

4. Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

5. Install dependencies:

```powershell
pip install -r requirements.txt
```

6. Create your `.env` file:

```powershell
copy .env.example .env
```

7. Open `.env` in Notepad and replace `PASTE_YOUR_KEY_HERE` with your VirusTotal API key.

8. Run the app:

```powershell
streamlit run app.py
```

## First test URL

Use a safe, mainstream test site first, such as:

```text
https://www.loc.gov
```

## Draft outputs

Generated Excel files are saved in:

```text
outputs/
```

## Notes for NIPR use

The app is designed so checks can fail gracefully. If a source is blocked or unavailable, the row should show `Needs Review` or allow analyst notes rather than breaking the workflow.

## Publish and deploy

### Publish code to GitHub

This project is already configured as a Git repository. To push new changes later:

```powershell
git add .
git commit -m "Describe your change"
git push
```

### Deploy on Streamlit Community Cloud

1. Go to `https://share.streamlit.io` and sign in with GitHub.
2. Click **New app** and select this repository.
3. Set the main file path to `app.py`.
4. In app settings, add a secret named `VT_API_KEY`.
5. Deploy.

For Streamlit secrets, use this format:

```toml
VT_API_KEY = "your_key_here"
```

Do not commit real API keys into this repository.
