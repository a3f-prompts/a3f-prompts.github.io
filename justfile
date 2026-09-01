test:
    node --test js/fit-ops.test.js js/fit-scanner.test.js

# Regenerate the demo page and its sample FIT image
demo:
    python3 gen-demo-fit.py
    python3 gen-demo.py

serve port='8080':
    python3 -m http.server {{port}}

clean:
    rm -f js/*.test.js js/test-helpers.js
