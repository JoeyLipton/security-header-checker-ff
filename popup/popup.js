document.addEventListener('DOMContentLoaded', function() {
    // UI elements
    const themeToggle = document.getElementById('theme-toggle');
    const enableToggle = document.getElementById('enable-toggle');
    const toggleLabel = document.getElementById('toggle-label');
    
    // Load user preferences for darkmode
    browser.storage.local.get(['darkMode', 'extensionEnabled']).then(result => {
      if (result.darkMode) {
        document.documentElement.setAttribute('data-theme', 'dark');
        themeToggle.checked = true;
      }

      // Check if extension is on
      if (result.extensionEnabled !== undefined) {
        enableToggle.checked = result.extensionEnabled;
        toggleLabel.textContent = result.extensionEnabled ? 'Enabled' : 'Disabled';
        toggleDisabledScreen(!result.extensionEnabled);
      }
    });
    
    // Theme handler
    themeToggle.addEventListener('change', function() {
      if (this.checked) {
        document.documentElement.setAttribute('data-theme', 'dark');
        browser.storage.local.set({ darkMode: true });
      } else {
        document.documentElement.removeAttribute('data-theme');
        browser.storage.local.set({ darkMode: false });
      }
    });
    
    // Enable/disable toggle handler
    enableToggle.addEventListener('change', function() {
      const isEnabled = this.checked;
      toggleLabel.textContent = isEnabled ? 'Enabled' : 'Disabled';
      
      toggleDisabledScreen(!isEnabled);
      
      browser.runtime.sendMessage({
        action: "setExtensionEnabled", 
        enabled: isEnabled
      }).then(() => {
        if (isEnabled) {
          loadHeaderData();
        }
      });
    });
    
    // Initial data load
    loadHeaderData();
  });
  
  // Toggle between enabled/disabled UI states
  function toggleDisabledScreen(show) {
    const disabledContainer = document.getElementById('disabled-container');
    const contentContainer = document.getElementById('content-container');
    
    disabledContainer.style.display = show ? 'block' : 'none';
    contentContainer.style.display = show ? 'none' : 'block';
  }
  
  // Load security header data from background script
  function loadHeaderData() {
    browser.runtime.sendMessage({action: "getHeaderData"})
      .then(response => {
        const { data, extensionEnabled } = response;
        
        toggleDisabledScreen(!extensionEnabled);
        
        if (extensionEnabled && data) {
          displayHeaderData(data);
        } else if (extensionEnabled) {
          displayNoData();
        }
      })
      .catch(error => {
        console.error("Error fetching header data:", error);
        displayError();
      });
  }
  
  // Display header analysis in popup
  function displayHeaderData(data) {
    // Set domain name
    document.getElementById('domain').textContent = data.domain;
    
    // Set score and apply styling
    const score = data.score;
    const scoreElement = document.getElementById('score-display');
    scoreElement.textContent = score;
    
    scoreElement.className = ''; // Reset classes
    if (score >= 90) {
      scoreElement.classList.add('score-a');
    } else if (score >= 80) {
      scoreElement.classList.add('score-b');
    } else if (score >= 70) {
      scoreElement.classList.add('score-c');
    } else if (score >= 60) {
      scoreElement.classList.add('score-d');
    } else {
      scoreElement.classList.add('score-f');
    }
    
    // Populate headers list
    const headersListElement = document.getElementById('headers-list');
    headersListElement.innerHTML = '';
    
    const headers = data.headers;
    
    // Header descriptions for educational context
    const headerDescriptions = {
      'content-security-policy': 'Controls resources the browser is allowed to load',
      'strict-transport-security': 'Forces browsers to use HTTPS for the website',
      'x-content-type-options': 'Prevents browsers from MIME-sniffing a response',
      'x-frame-options': 'Protects against clickjacking attacks',
      'referrer-policy': 'Controls how much referrer information is included with requests',
      'permissions-policy': 'Controls which browser features can be used on the page',
      'cross-origin-resource-policy': 'Controls which websites can load this resource',
      'cross-origin-opener-policy': 'Controls how the page interacts with other browsing contexts',
      'cross-origin-embedder-policy': 'Controls which cross-origin resources can be loaded'
    };
    
    // Render each header
    Object.keys(headerDescriptions).forEach(header => {
      const headerValue = headers[header];
      const headerElement = document.createElement('div');
      
      if (headerValue) {
        const isOptimal = isHeaderOptimal(header, headerValue);
        headerElement.className = `header-item ${isOptimal ? 'header-present' : 'header-suboptimal'}`;
        
        headerElement.innerHTML = `
          <div class="header-name">${formatHeaderName(header)}</div>
          <div>${headerDescriptions[header]}</div>
          <div class="header-value">${headerValue}</div>
        `;
      } else {
        headerElement.className = 'header-item header-missing';
        headerElement.innerHTML = `
          <div class="header-name">${formatHeaderName(header)}</div>
          <div>${headerDescriptions[header]}</div>
          <div><em>Not implemented</em></div>
        `;
      }
      
      headersListElement.appendChild(headerElement);
    });
    
    // Generate recommendations section
    generateRecommendations(headers);
  }
  
  // Check if header meets best practices
  function isHeaderOptimal(header, value) {
    switch (header) {
      case 'content-security-policy':
        return !value.includes("unsafe-inline") && !value.includes("unsafe-eval");
      case 'strict-transport-security':
        return value.includes("max-age=") && 
               parseInt(value.match(/max-age=(\d+)/)[1]) >= 15768000 &&
               value.includes("includeSubDomains");
      case 'x-content-type-options':
        return value === 'nosniff';
      case 'x-frame-options':
        return value === 'DENY' || value === 'SAMEORIGIN';
      case 'referrer-policy':
        return ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'].includes(value);
      default:
        return true;
    }
  }
  
  // Generate improvement recommendations
  function generateRecommendations(headers) {
    const recommendationsElement = document.getElementById('recommendations-list');
    recommendationsElement.innerHTML = '';
    
    // CSP recommendations
    if (!headers['content-security-policy']) {
      addRecommendation(
        "Implement Content-Security-Policy", 
        "This header helps prevent XSS attacks by controlling which resources can be loaded.",
        "default-src 'self'; script-src 'self'; object-src 'none';"
      );
    } else if (headers['content-security-policy'].includes("unsafe-inline") || 
               headers['content-security-policy'].includes("unsafe-eval")) {
      addRecommendation(
        "Strengthen Content-Security-Policy", 
        "Avoid using 'unsafe-inline' and 'unsafe-eval' as they reduce the effectiveness of CSP.",
        "Replace 'unsafe-inline' with nonces or hashes for specific scripts."
      );
    }
    
    // HSTS recommendations
    if (!headers['strict-transport-security']) {
      addRecommendation(
        "Implement Strict-Transport-Security", 
        "This header ensures that all connections to your site use HTTPS, protecting against downgrade attacks.",
        "strict-transport-security: max-age=31536000; includeSubDomains"
      );
    }
    
    // X-Content-Type-Options recommendation
    if (!headers['x-content-type-options']) {
      addRecommendation(
        "Add X-Content-Type-Options header", 
        "This header prevents browsers from MIME-sniffing, which can lead to security vulnerabilities.",
        "x-content-type-options: nosniff"
      );
    }
    
    // X-Frame-Options recommendation
    if (!headers['x-frame-options']) {
      addRecommendation(
        "Implement X-Frame-Options", 
        "This header protects against clickjacking attacks by controlling how your page can be framed.",
        "x-frame-options: DENY"
      );
    }
    
    // Show "all good" message if no recommendations
    if (recommendationsElement.children.length === 0) {
      const noRecsElement = document.createElement('div');
      noRecsElement.textContent = "No critical recommendations. This site has good security header implementation!";
      recommendationsElement.appendChild(noRecsElement);
    }
  }
  
  // Add a recommendation to the list
  function addRecommendation(title, description, example) {
    const recommendationsElement = document.getElementById('recommendations-list');
    const recommendationElement = document.createElement('div');
    recommendationElement.className = 'recommendation';
    recommendationElement.innerHTML = `
      <strong>${title}</strong>
      <p>${description}</p>
      <div class="header-value">${example}</div>
    `;
    recommendationsElement.appendChild(recommendationElement);
  }
  
  // Format header name for display (e.g., content-security-policy → Content-Security-Policy)
  function formatHeaderName(header) {
    return header.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join('-');
  }
  
  // Display message when no data is available
  function displayNoData() {
    document.getElementById('domain').textContent = "No header data available";
    document.getElementById('score-display').textContent = "--";
    document.getElementById('headers-list').innerHTML = "<p>Please visit a website to analyze its security headers.</p>";
    document.getElementById('recommendations-list').innerHTML = "";
  }
  
  // Display error message
  function displayError() {
    document.getElementById('domain').textContent = "Error loading data";
    document.getElementById('score-display').textContent = "--";
    document.getElementById('headers-list').innerHTML = "<p>An error occurred while analyzing security headers.</p>";
    document.getElementById('recommendations-list').innerHTML = "";
  }