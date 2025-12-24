// home.js
let inFrame;

try {
  inFrame = window !== top;
} catch (e) {
  inFrame = true;
}
if (!localStorage.getItem("ab")) localStorage.setItem("ab", true);
if (!inFrame && !navigator.userAgent.includes("Firefox") && localStorage.getItem("ab") === "true") {
  const popup = open("about:blank", "_blank");
  setTimeout(() => {
    if (!popup || popup.closed) {
      alert("Please allow popups for this site. Doing so will allow us to open the site in a about:blank tab and preventing this site from showing up in your history. You can turn this off in the site settings.");
    } else {
      const doc = popup.document;
      const iframe = doc.createElement("iframe");
      const style = iframe.style;
      const link = doc.createElement("link");

      const name = localStorage.getItem("name") || "My Drive - Google Drive";
      const icon = localStorage.getItem("icon") || "https://ssl.gstatic.com/docs/doclist/images/drive_2022q3_32dp.png";

      doc.title = name;
      link.rel = "icon";
      link.href = icon;

      iframe.src = location.href;
      style.position = "fixed";
      style.top = style.bottom = style.left = style.right = 0;
      style.border = style.outline = "none";
      style.width = style.height = "100%";

      doc.head.appendChild(link);
      doc.body.appendChild(iframe);

      const pLink = localStorage.getItem(encodeURI("pLink")) || getRandomUrl();
      location.replace(pLink);

      const script = doc.createElement("script");
      script.textContent = `
      window.onbeforeunload = function (event) {
        const confirmationMessage = 'Leave Site?';
        (event || window.event).returnValue = confirmationMessage;
        return confirmationMessage;
      };
    `;
      doc.head.appendChild(script);
    }
  }, 2000);
}
// Particles
document.addEventListener("DOMContentLoaded", event => {
  // Enable particles by default for rain effect (except on tabs page)
  if (!window.localStorage.getItem("particles")) {
    window.localStorage.setItem("particles", "true");
  }
  if (window.localStorage.getItem("particles") === "true" && window.location.pathname !== '/d') {
    const particlesConfig = {
      particles: {
        number: {
          value: 800,
          density: {
            enable: true,
            value_area: 400,
          },
        },
        color: {
          value: "#ffffff",
        },
        shape: {
          type: "circle",
          stroke: {
            width: 0,
            color: "#ffffff",
          },
          polygon: {
            nb_sides: 5,
          },
          image: {
            src: "img/github.svg",
            width: 100,
            height: 100,
          },
        },
        opacity: {
          value: 0.6,
          random: false,
          anim: {
            enable: false,
            speed: 1,
            opacity_min: 0.3,
            sync: false,
          },
        },
        size: {
          value: 2,
          random: true,
          anim: {
            enable: false,
            speed: 40,
            size_min: 4,
            sync: false,
          },
        },
        line_linked: {
          enable: false,
          distance: 150,
          color: "#ffffff",
          opacity: 0.4,
          width: 1,
        },
        move: {
          enable: true,
          speed: 20,
          direction: "bottom",
          random: false,
          straight: true,
          out_mode: "out",
          bounce: false,
          attract: {
            enable: false,
            rotateX: 600,
            rotateY: 1200,
          },
        },
      },
      interactivity: {
        detect_on: "canvas",
        events: {
          onhover: {
            enable: true,
            mode: "repulse",
          },
          onclick: {
            enable: false,
            mode: "push",
          },
          resize: true,
        },
        modes: {
          grab: {
            distance: 400,
            line_linked: {
              opacity: 1,
            },
          },
          bubble: {
            distance: 400,
            size: 40,
            duration: 2,
            opacity: 8,
            speed: 3,
          },
          repulse: {
            distance: 40,
            duration: 0.4,
          },
          push: {
            particles_nb: 4,
          },
          remove: {
            particles_nb: 2,
          },
        },
      },
      retina_detect: true,
    };
    particlesJS("particles-js", particlesConfig);
    
    // Add rain bouncing off search bar functionality
    setTimeout(() => {
      const pJS = window.pJSDom && window.pJSDom[0] ? window.pJSDom[0].pJS : null;
      if (pJS) {
        // Store original update function
        const originalUpdate = pJS.fn.particlesUpdate;
        
        // Create splash particles array
        const splashParticles = [];
        
        // Override particles update to add collision detection
        pJS.fn.particlesUpdate = function() {
          // Call original update
          originalUpdate.call(this);
          
          // Get search bar element and its position
          const searchContainer = document.querySelector('.search-container');
          const searchBar = document.querySelector('.truncate');
          if (!searchContainer || !searchBar) return;
          
          const containerRect = searchContainer.getBoundingClientRect();
          const rect = searchBar.getBoundingClientRect();
          const searchBarTop = rect.top;
          const searchBarBottom = rect.bottom;
          const searchBarLeft = rect.left;
          const searchBarRight = rect.right;
          
          // Check each particle for collision with search bar
          for (let i = 0; i < pJS.particles.array.length; i++) {
            const p = pJS.particles.array[i];
            
            // Check if particle is within horizontal bounds of search bar
            if (p.x >= searchBarLeft && p.x <= searchBarRight) {
              // Check if particle is hitting the top of the search bar
              if (p.y >= searchBarTop - 2 && p.y <= searchBarTop + 2) {
                // Create splash effect
                createSplashEffect(p.x, p.y);
                
                // Bounce the particle
                p.vy = Math.abs(p.vy) * 0.8; // Reverse direction and reduce speed
                p.y = searchBarTop - 2; // Position just above the search bar
                
                // Add some horizontal spread for realism
                p.vx += (Math.random() - 0.5) * 2;
              }
            }
          }
          
          // Update and draw splash particles
          updateSplashParticles();
        };
        
        // Function to create splash effect
        function createSplashEffect(x, y) {
          const splashCount = 8; // Number of splash particles
          for (let i = 0; i < splashCount; i++) {
            const angle = (Math.PI * 2 * i) / splashCount;
            const speed = Math.random() * 2 + 1;
            
            splashParticles.push({
              x: x,
              y: y,
              vx: Math.cos(angle) * speed,
              vy: Math.sin(angle) * speed - 2, // Initial upward velocity
              life: 1.0,
              size: Math.random() * 2 + 1
            });
          }
        }
        
        // Function to update splash particles
        function updateSplashParticles() {
          const canvas = document.querySelector('.particles-js-canvas-el');
          if (!canvas) return;
          
          const ctx = canvas.getContext('2d');
          const rect = canvas.getBoundingClientRect();
          
          // Draw splash particles
          for (let i = splashParticles.length - 1; i >= 0; i--) {
            const sp = splashParticles[i];
            
            // Update position
            sp.x += sp.vx;
            sp.y += sp.vy;
            sp.vy += 0.1; // Gravity
            sp.life -= 0.02; // Fade out
            
            // Draw particle
            ctx.save();
            ctx.globalAlpha = sp.life;
            ctx.fillStyle = '#ffffff';
            ctx.beginPath();
            ctx.arc(sp.x - rect.left, sp.y - rect.top, sp.size, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
            
            // Remove dead particles
            if (sp.life <= 0) {
              splashParticles.splice(i, 1);
            }
          }
        }
        
        // Override the draw function to ensure splash particles are drawn
        const originalDraw = pJS.fn.draw;
        pJS.fn.draw = function() {
          // Call original draw
          originalDraw.call(this);
          
          // Draw splash particles on top
          updateSplashParticles();
        };
      }
    }, 1000);
  }
});
// Splash texts
const SplashT = [
  "Over 8 Million Users since 2023",
  "Fastest growing proxy server",
  "Made by xBubbo modded by ilikepancakes.ink",
  "big smoke",
  "Thanks for using the site",
  "slaap lekker en laat de bedwantsen je niet bijten :3",
  "you wouldn't download a car",
  "check out my website ilikepancakes.ink",
  "Check out the settings page",
  ":3",
];

let SplashI = Math.floor(Math.random() * SplashT.length);
const SplashE = document.getElementById("splash");

function US() {
  SplashI = (SplashI + 1) % SplashT.length;
  SplashE.innerText = SplashT[SplashI];
}

SplashE.innerText = SplashT[SplashI];

SplashE.addEventListener("click", US);

// Rotating Welcome Messages
const welcomeMessages = [
  "Welcome",        // English
  "Bienvenido",     // Spanish
  "Welkom",         // Dutch
  "Willkommen",     // German
  "Bienvenue",      // French
  "Välkommen",      // Swedish
  "ようこそ",       // Japanese
  "환영합니다",     // Korean
  "欢迎",           // Chinese
  "Добро пожаловать", // Russian
  "أهلا وسهلا",     // Arabic
  "მოგესალმებით",   // Georgian
  "Bem-vindo",      // Portuguese
  "Dobrodošli",     // Croatian
  "Vitajte"         // Slovakian
];

let currentMessageIndex = 0;
const welcomeText = document.getElementById("welcome-text");

function rotateWelcomeMessage() {
  // Fade out
  welcomeText.classList.add("fade-out");

  setTimeout(() => {
    // Change text
    currentMessageIndex = (currentMessageIndex + 1) % welcomeMessages.length;
    welcomeText.textContent = welcomeMessages[currentMessageIndex];

    // Fade in
    welcomeText.classList.remove("fade-out");
  }, 1000); // Half of transition time
}

// Start rotating after page load
setTimeout(() => {
  rotateWelcomeMessage();
  setInterval(rotateWelcomeMessage, 3000); // Change every 3 seconds
}, 2000); // Start after 2 seconds

// Random URL
function getRandomUrl() {
  const randomUrls = [
    "https://kahoot.it",
    "https://classroom.google.com",
    "https://drive.google.com",
    "https://google.com",
    "https://docs.google.com",
    "https://slides.google.com",
    "https://www.nasa.gov",
    "https://blooket.com",
    "https://clever.com",
    "https://edpuzzle.com",
    "https://khanacademy.org",
    "https://wikipedia.org",
    "https://dictionary.com",
  ];
  return randomUrls[randRange(0, randomUrls.length)];
}

function randRange(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}
