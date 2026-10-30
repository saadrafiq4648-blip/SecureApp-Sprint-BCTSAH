# SecureShare (SecureApp-Sprint-TeamAlpha)

Secure file-sharing and collaboration platform hardened during the CYC386 1-Week DevSecOps Sprint.

## Build, Run, and Test Instructions

    # build
    make -C native                        # builds libmetaparse.so
    pip install -r requirements.txt

    # run
    flask --app src.app run --port 5000   # dev server
    docker compose up --build             # or: full stack with LibreOffice

    # test
    pytest -q
