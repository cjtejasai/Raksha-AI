# Publishing Raksha to Git & PyPI

Complete guide for publishing your Raksha security SDK.

---

## 📦 Part 1: Publishing to GitHub

### Step 1: Create GitHub Repository

Go to https://github.com/new and create a new repository:
- **Name:** `raksha` (or `raksha-security`)
- **Description:** Framework-agnostic AI security SDK with comprehensive threat detection for LLMs and AI agents
- **Visibility:** Public (for open source) or Private
- **Don't initialize** with README (we already have one)

### Step 2: Connect Local Repo to GitHub

```bash
# Add remote (replace USERNAME with your GitHub username)
git remote add origin https://github.com/USERNAME/raksha.git

# Or if using SSH
git remote add origin git@github.com:USERNAME/raksha.git

# Verify remote was added
git remote -v
```

### Step 3: Stage and Commit Changes

```bash
# Stage all changes (documentation cleanup + notebook updates)
git add .

# Create commit
git commit -m "Major update: Consolidate docs, add support agent demo

- Merged all documentation into single comprehensive README.md
- Removed temporary planning and review documents
- Updated Jupyter notebook with customer support agent demo
- Integrated Raksha security with Phoenix observability
- Added real-world test cases (safe and malicious)
- Updated .gitignore for logs and temp files"

# Verify commit
git log --oneline -1
```

### Step 4: Push to GitHub

```bash
# Push to main branch
git push -u origin main

# For subsequent pushes, just use:
git push
```

### Step 5: Verify on GitHub

1. Go to your repository URL: `https://github.com/USERNAME/raksha`
2. Check that all files are there
3. Verify README.md displays properly

---

## 🚀 Part 2: Publishing to PyPI

### Prerequisites

Install build tools:
```bash
pip install --upgrade pip
pip install --upgrade build twine
```

### Step 1: Verify Package Configuration

Check `pyproject.toml` is properly configured:
- ✅ Package name: `raksha`
- ✅ Version: `0.1.0`
- ✅ Description
- ✅ License
- ✅ Dependencies

### Step 2: Build Distribution Files

```bash
# Clean old builds
rm -rf build/ dist/ *.egg-info src/*.egg-info

# Build source distribution and wheel
python -m build

# You should see:
# dist/
#   raksha-0.1.0.tar.gz
#   raksha-0.1.0-py3-none-any.whl
```

### Step 3: Test on TestPyPI First (Recommended)

**Create TestPyPI Account:**
1. Go to https://test.pypi.org/account/register/
2. Verify your email
3. Create API token at https://test.pypi.org/manage/account/token/
   - Token name: `raksha-upload`
   - Scope: Entire account (or specific project)
   - **Save the token** (starts with `pypi-`)

**Upload to TestPyPI:**
```bash
# Upload
python -m twine upload --repository testpypi dist/*

# When prompted:
# Username: __token__
# Password: pypi-xxxxxxxxxxxx (your token)

# Or configure ~/.pypirc to avoid prompting (see below)
```

**Test Installation from TestPyPI:**
```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ raksha

# Test it works
python -c "from raksha import SecurityScanner; print('✅ Import successful')"

# Deactivate
deactivate
rm -rf test_env
```

### Step 4: Publish to Real PyPI

**Create PyPI Account:**
1. Go to https://pypi.org/account/register/
2. Verify your email
3. Enable 2FA (required for new projects)
4. Create API token at https://pypi.org/manage/account/token/
   - Token name: `raksha-upload`
   - Scope: Entire account (or wait until after first upload to create project-scoped token)
   - **Save the token securely**

**Upload to PyPI:**
```bash
# Upload
python -m twine upload dist/*

# When prompted:
# Username: __token__
# Password: pypi-xxxxxxxxxxxx (your PyPI token)
```

**Verify:**
```bash
# Install from real PyPI
pip install raksha

# Test
python -c "from raksha import SecurityScanner; print('✅ Raksha installed!')"
```

---

## 🔐 Optional: Configure ~/.pypirc (Avoid Repeated Password Entry)

Create `~/.pypirc`:
```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR_PYPI_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TESTPYPI_TOKEN_HERE
```

**Important:** Add to `.gitignore`:
```bash
echo "~/.pypirc" >> ~/.gitignore
```

---

## 📝 Post-Publishing Checklist

### After GitHub Push:
- [ ] Add repository description on GitHub
- [ ] Add topics: `python`, `security`, `llm`, `ai-safety`, `owasp`
- [ ] Create release/tag for v0.1.0
- [ ] Add badge to README: `![PyPI](https://img.shields.io/pypi/v/raksha)`
- [ ] Add GitHub Actions for CI/CD (optional)
- [ ] Star your own repo (why not! 😄)

### After PyPI Publish:
- [ ] Verify package page: https://pypi.org/project/raksha/
- [ ] Check that README renders correctly
- [ ] Test installation: `pip install raksha`
- [ ] Update README with installation instructions
- [ ] Share on social media / communities
- [ ] Submit to relevant newsletters (e.g., Python Weekly)

---

## 🔄 Updating the Package

### For Code Changes:

1. **Update version** in `pyproject.toml`:
   ```toml
   version = "0.1.1"  # Bump version
   ```

2. **Commit changes:**
   ```bash
   git add .
   git commit -m "Release v0.1.1: Bug fixes and improvements"
   git tag v0.1.1
   git push && git push --tags
   ```

3. **Rebuild and upload:**
   ```bash
   rm -rf dist/
   python -m build
   python -m twine upload dist/*
   ```

### Semantic Versioning:
- `0.1.0` → `0.1.1` - Bug fixes (PATCH)
- `0.1.0` → `0.2.0` - New features, backwards compatible (MINOR)
- `0.1.0` → `1.0.0` - Breaking changes (MAJOR)

---

## 🐛 Troubleshooting

### "Repository already exists"
If package name is taken on PyPI, choose a different name:
- `raksha-security`
- `raksha-ai`
- `raksha-llm-guard`

Update in `pyproject.toml`:
```toml
name = "raksha-security"
```

### "Invalid distribution file"
```bash
# Clean everything
rm -rf build/ dist/ *.egg-info src/*.egg-info
python -m build
```

### "403 Forbidden"
- Wrong API token
- Token doesn't have upload permissions
- 2FA not enabled on PyPI account

### Git Push Rejected
```bash
# Pull first (if remote has changes)
git pull --rebase origin main
git push
```

---

## 📚 Additional Resources

- **PyPI Guide:** https://packaging.python.org/tutorials/packaging-projects/
- **GitHub Docs:** https://docs.github.com/en/get-started
- **Semantic Versioning:** https://semver.org/
- **Twine Docs:** https://twine.readthedocs.io/

---

## 🎉 Quick Commands Reference

```bash
# ============== GIT ==============
git add .
git commit -m "Your message"
git push

# ============== PyPI ==============
# Build
python -m build

# Test upload
python -m twine upload --repository testpypi dist/*

# Real upload
python -m twine upload dist/*

# Test install
pip install raksha

# ============== Both ==============
# For new version
# 1. Update version in pyproject.toml
# 2. Clean and rebuild
rm -rf dist/ && python -m build
# 3. Commit and tag
git add . && git commit -m "Release vX.X.X" && git tag vX.X.X
# 4. Push
git push && git push --tags
# 5. Upload to PyPI
python -m twine upload dist/*
```

---

**Good luck with your launch! 🚀**