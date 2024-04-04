# Audit Report

This tool generates a report of issues from dependency and supply chain vulnerabilities reported by [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot).

## Asciidoc Setup

Asciidoc is a ruby project and depends on various ruby gems to make things work

I used the MacOS version and i followed the instructions on this link [here](https://asciidoctor.org/docs/install-asciidoctor-macos/#rvm-procedure-recommended)

### Set Up

Getting started with general prerequisites set up:

1.  Install ruby ≥ 2.3 see [documentation](https://www.ruby-lang.org/en/documentation/installation/)

    ```sh
    brew intall ruby
    ```

    _Recommended_: Install ruby version using [RVM (Ruby Version Manager)](https://docs.asciidoctor.org/reveal.js-converter/latest/setup/ruby-setup/#prerequisites)

    ```sh
    \curl -sSL https://get.rvm.io | bash -s stable --rails
    ```

1.  Install `asciidoc` see [docs](https://docs.asciidoctor.org/asciidoctor/latest/install/)

    ```sh
    gem install asciidoc
    ```

1.  Install `asciidoc-pdf` see [docs]()

    ```sh
    gem install asciidoc-pdf
    ```

1.  Install `pygments`

    ```sh
    pip install 'pygments[plugins]'
    ```

## Auto-Generate Report from Dependabot alerts

1. Set up [Dependabot]() on project you are auditing

1. Save results from to [`results.json`]()

   ```sh
   gh api \
     -H "Accept: application/vnd.github+json" \
     -H "X-GitHub-Api-Version: 2022-11-28" \
     /repos/USER/REPO/dependabot/alerts >> results.json
   ```

   **Common Errors**: Bad Authentication, 401

   Go to [Developer Settings](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) and give Fine-grained tokens read and write access to Dependabot alerts

   - After updating dependabot access re-authenticate:

   ```sh
   gh auth refresh
   # Continue steps in browser and use the code generated in your terminal to authenticate, then do step 1 again
   ```

1. Run formating command reads the json and converts it into `.asciidoc` format report:

   ```sh
   python3 main.py
   ```

1. Convert `.asciidoc` report to `.pdf` with `asciidoc-pdf`:

   ```sh
   asciidoctor -r asciidoctor-pdf -b pdf report/README.adoc
   ```

1. Include URI reference content see [documentation](https://docs.asciidoctor.org/asciidoc/latest/directives/include-uri/)
   ```sh
   asciidoctor -a allow-uri-read filename.adoc
   ```
