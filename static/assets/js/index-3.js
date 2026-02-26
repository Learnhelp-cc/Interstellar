// index.js
// Polyfill for older browsers
if (!window.addEventListener) {
  window.addEventListener = function(event, callback) {
    if (window.attachEvent) {
      window.attachEvent('on' + event, callback);
    } else {
      window['on' + event] = callback;
    }
  };
}

// Additional polyfills for better browser compatibility
if (!window.fetch) {
  window.fetch = function() {
    return Promise.reject(new Error('Fetch API not supported'));
  };
}

if (!window.Promise) {
  window.Promise = function() {
    throw new Error('Promise not supported');
  };
}

if (!window.localStorage) {
  window.localStorage = {
    getItem: function() { return null; },
    setItem: function() {},
    removeItem: function() {},
    clear: function() {}
  };
}

// Ensure service worker registration works across browsers
window.addEventListener("load", function() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register("../sw.js?v=2025-04-15", {
      scope: "/a/",
    }).catch(function(error) {
      console.warn('Service worker registration failed:', error);
    });
  }
});

let xl;

try {
  xl = window.top.location.pathname === "/d";
} catch {
  try {
    xl = window.parent.location.pathname === "/d";
  } catch {
    xl = false;
  }
}

const form = document.getElementById("fv");
const input = document.getElementById("input");

// Ensure elements exist before adding event listeners
if (form && input) {
  // Add event listener with fallback for older browsers
  if (form.addEventListener) {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      try {
        if (xl) processUrl(input.value, "");
        else processUrl(input.value, "/d");
      } catch {
        processUrl(input.value, "/d");
      }
    });
  } else if (form.attachEvent) {
    // IE8 and below fallback
    form.attachEvent("onsubmit", async function(event) {
      event.preventDefault();
      try {
        if (xl) processUrl(input.value, "");
        else processUrl(input.value, "/d");
      } catch {
        processUrl(input.value, "/d");
      }
    });
  }
} else {
  // Fallback if elements don't exist yet
  window.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById("fv");
    const input = document.getElementById("input");
    
    if (form && input) {
      if (form.addEventListener) {
        form.addEventListener("submit", async event => {
          event.preventDefault();
          try {
            if (xl) processUrl(input.value, "");
            else processUrl(input.value, "/d");
          } catch {
            processUrl(input.value, "/d");
          }
        });
      }
    }
  });
}
async function processUrl(value, path) {
  let url = value.trim();
  const engine = localStorage.getItem("engine");
  const searchUrl = engine ? engine : "https://duckduckgo.com/?q=";

  if (!isUrl(url)) {
    url = searchUrl + url;
  } else if (!(url.startsWith("https://") || url.startsWith("http://"))) {
    url = `https://${url}`;
  }

  // Log to search history with fallback for browsers without fetch
  try {
    const deviceToken = localStorage.getItem('deviceToken');
    if (deviceToken && window.fetch) {
      await fetch('/api/search-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceToken: deviceToken,
          url: url,
          title: value.trim() // Use original input as title
        })
      });
    }
  } catch (error) {
    console.error('Failed to log search history:', error);
  }

  // Ensure sessionStorage is available
  if (window.sessionStorage) {
    sessionStorage.setItem("GoUrl", __uv$config.encodeUrl(url));
  }

  const dy = localStorage.getItem("dy");

  if (dy === "true") {
    window.location.href = `/a/q/${__uv$config.encodeUrl(url)}`;
  } else if (path) {
    location.href = path;
  } else {
    window.location.href = `/a/${__uv$config.encodeUrl(url)}`;
  }
}

function go(value) {
  processUrl(value, "/d");
}

function blank(value) {
  processUrl(value);
}

function dy(value) {
  processUrl(value, `/a/q/${__uv$config.encodeUrl(value)}`);
}

function isUrl(val = "") {
  // Enhanced URL detection with better browser compatibility
  if (typeof val !== 'string') {
    return false;
  }
  
  val = val.trim();
  
  // Check for protocol
  if (/^https?:\/\//i.test(val)) {
    return true;
  }
  
  // Check for common domain patterns
  if (val.includes(".") && val.substr(0, 1) !== " " && val.length > 3) {
    // Additional check for valid domain format
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    const parts = val.split('/');
    const domain = parts[0];
    
    if (domainPattern.test(domain)) {
      return true;
    }
  }
  
  return false;
}
