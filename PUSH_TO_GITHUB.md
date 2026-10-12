# Upload source to GitHub repository 026

To install the prepared source archive and publish it to the currently empty
repository, run these commands in Ubuntu after downloading and extracting it:

```bash
python3 --version
git --version
cd 026
python3 Main.py --test
python3 Main.py

git init
git branch -M main
git add README.md LICENSE .gitignore .env.example requirements.in requirements.txt pyproject.toml
git commit -m "Initialize SAL packaging and documentation"
git add Main.py configs src docs
git commit -m "Implement cryptographic ledger, erasure and experiments"
git add tests .github PUSH_TO_GITHUB.md
git commit -m "Add tests and continuous integration"
git remote add origin https://github.com/Verlopat/026.git
git push -u origin main
```

GitHub authentication may prompt for a credential or use an existing credential
helper. If `origin` already exists, use `git remote set-url origin
https://github.com/Verlopat/026.git` in place of `git remote add origin`.
**Do not** add generated output directories to Git. The `.gitignore` already
excludes `output/` and run data by default.
