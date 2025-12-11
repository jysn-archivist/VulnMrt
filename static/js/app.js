// static/js/app.js

// VULN: Exposed API key with flag
const VULNMART_API_KEY = "FLAG{exposed_frontend_api_key}";

function searchApi(term) {
  return fetch("/api/search?term=" + encodeURIComponent(term) + "&key=" + VULNMART_API_KEY)
    .then(r => r.json())
    .then(data => {
      console.log("Search result:", data);
    });
}

// Tiny helper to show off a reflected XSS payload idea in dev console
console.log("Try /products?search=<script>alert('FLAG{reflected_xss_search}')</script>");