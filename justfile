test:
    node --test js/fit-ops.test.js js/fit-scanner.test.js

serve port='8080':
    python3 -m http.server {{port}}

clean:
    rm -f js/*.test.js js/test-helpers.js
