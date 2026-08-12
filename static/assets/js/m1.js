// main.js
let qp;

try {
  qp = window.top.location.pathname === "/d";
} catch {
  try {
    qp = window.parent.location.pathname === "/d";
  } catch {
    qp = false;
  }
}

// Version fetch function
async function updateVersion() {
  const versionElement = document.getElementById('version-info');
  if (!versionElement) return;

  try {
    const response = await fetch('/api/version');
    if (!response.ok) {
      throw new Error();
    }
    const data = await response.json();
    versionElement.textContent = `Version: ${data.version}`;
  } catch (error) {
    versionElement.textContent = 'Version: Unable to fetch';
  }
}

// Last updated fetch function
async function updateLastUpdated() {
  const lastUpdatedElement = document.getElementById('last-updated');
  if (!lastUpdatedElement) return;

  try {
    const response = await fetch('https://api.github.com/repos/Learnhelp-cc/Interstellar/commits?per_page=1');
    if (!response.ok) {
      throw new Error();
    }
    const commits = await response.json();
    if (commits && commits.length > 0) {
      const commitDate = new Date(commits[0].commit.author.date);
      const formattedDate = commitDate.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
      lastUpdatedElement.textContent = `Last Updated: ${formattedDate}`;
    } else {
      throw new Error();
    }
  } catch (error) {
    lastUpdatedElement.textContent = 'Last Updated: Unable to fetch';
  }
}

// Connection status functions
async function getClientIP() {
  try {
    const response = await fetch('https://wtfismyip.com/json');
    const data = await response.json();
    return data.YourFuckingIPAddress;
  } catch (error) {
    return 'unknown';
  }
}

async function measurePing() {
  try {
    const start = Date.now();
    await fetch('/api/server-info', { method: 'HEAD' });
    const end = Date.now();
    return end - start;
  } catch (error) {
    return 'unknown';
  }
}

async function updateConnectionStatus() {
  const statusElement = document.getElementById('connection-status');
  if (!statusElement) return;

  try {
    // Get server info
    const serverResponse = await fetch('/api/server-info');
    const serverData = await serverResponse.json();

    // Get client IP
    const clientIP = await getClientIP();

    // Measure ping
    const ping = await measurePing();

    // Update status
    const statusText = `connected to ${serverData.serverIP} via cloudflare tunnel (${serverData.domain}), from ${clientIP}. ping: ${ping}ms`;
    statusElement.textContent = statusText;
    statusElement.title = statusText; // Show full text on hover

    // Update periodically
    setTimeout(updateConnectionStatus, 30000); // Update every 30 seconds
  } catch (error) {
    statusElement.textContent = 'Connection status unavailable';
    // Retry after 10 seconds on error
    setTimeout(updateConnectionStatus, 10000);
  }
}

document.addEventListener("DOMContentLoaded", () => {


  const nav = document.querySelector(".f-nav");

  if (nav) {
    const html = `
      <div id="icon-container">
        <div id="connection-status" class="status-display">Loading connection status...</div>
      </div>
      <div class="f-nav-right">
        <a class="navbar-link" href="/./account"><i class="fa-solid fa-user navbar-icon"></i><an>&#77;&#121;&#32;</an><an>&#65;&#99;&#99;&#111;&#117;&#110;&#116;</an></a>
        ${qp ? "" : '<a class="navbar-link" href="/./d"><i class="fa-solid fa-laptop navbar-icon"></i><an>&#84;&#97;</an><an>&#98;&#115;</an></a>'}
        <a class="navbar-link" href="/./c"><i class="fa-solid fa-gear navbar-icon settings-icon"></i><an>&#83;&#101;&#116;</an><an>&#116;&#105;&#110;&#103;</an></a>
      </div>`;
    nav.innerHTML = html;

    // Initialize connection status
    updateConnectionStatus();
  }

  // LocalStorage Setup for 'dy'
  if (localStorage.getItem("dy") === null || localStorage.getItem("dy") === undefined) {
    localStorage.setItem("dy", "false");
  }

  // Favicon and Name Logic
  const icon = document.getElementById("tab-favicon");
  const name = document.getElementById("t");
  const selectedValue = localStorage.getItem("selectedOption");

  function setCloak(nameValue, iconUrl) {
    const customName = localStorage.getItem("CustomName");
    const customIcon = localStorage.getItem("CustomIcon");

    let FinalNameValue = nameValue;
    let finalIconUrl = iconUrl;

    if (customName) {
      FinalNameValue = customName;
    }
    if (customIcon) {
      finalIconUrl = customIcon;
    }

    if (finalIconUrl) {
      icon.setAttribute("href", finalIconUrl);
      localStorage.setItem("icon", finalIconUrl);
    }
    if (FinalNameValue) {
      name.textContent = FinalNameValue;
      localStorage.setItem("name", FinalNameValue);
    }
  }

  const options = {
    Google: { name: "Google", icon: "/assets/media/favicon/google.png" },
    "Savvas Realize": {
      name: "Savvas Realize",
      icon: "/assets/media/favicon/savvas-realize.png",
    },
    SmartPass: {
      name: "SmartPass",
      icon: "/assets/media/favicon/smartpass.png",
    },
    "World Book Online - Super Home": {
      name: "Super Home Page",
      icon: "/assets/media/favicon/wbo.ico",
    },
    "World Book Online - Student": {
      name: "WBO Student | Home Page",
      icon: "/assets/media/favicon/wbo.ico",
    },
    "World Book Online - Timelines": {
      name: "Timelines - Home Page",
      icon: "/assets/media/favicon/wbo.ico",
    },
    Naviance: {
      name: "Naviance Student",
      icon: "/assets/media/favicon/naviance.png",
    },
    "PBS Learning Media": {
      name: "PBS LearningMedia | Teaching Resources For Students And Teachers",
      icon: "/assets/media/favicon/pbslearningmedia.ico",
    },
    "PBS Learning Media Student Home": {
      name: "Student Homepage | PBS LearningMedia",
      icon: "/assets/media/favicon/pbslearningmedia.ico",
    },
    Drive: {
      name: "My Drive - Google Drive",
      icon: "/assets/media/favicon/drive.png",
    },
    Classroom: { name: "Home", icon: "/assets/media/favicon/classroom.png" },
    Schoology: {
      name: "Home | Schoology",
      icon: "/assets/media/favicon/schoology.png",
    },
    Gmail: { name: "Gmail", icon: "/assets/media/favicon/gmail.png" },
    Clever: {
      name: "Clever | Portal",
      icon: "/assets/media/favicon/clever.png",
    },
    Khan: {
      name: "Dashboard | Khan Academy",
      icon: "/assets/media/favicon/khan.png",
    },
    Dictionary: {
      name: "Dictionary.com | Meanings & Definitions of English Words",
      icon: "/assets/media/favicon/dictionary.png",
    },
    Thesaurus: {
      name: "Synonyms and Antonyms of Words | Thesaurus.com",
      icon: "/assets/media/favicon/thesaurus.png",
    },
    Campus: {
      name: "Infinite Campus",
      icon: "/assets/media/favicon/campus.png",
    },
    IXL: { name: "IXL | Dashboard", icon: "/assets/media/favicon/ixl.png" },
    Canvas: { name: "Dashboard", icon: "/assets/media/favicon/canvas.png" },
    LinkIt: { name: "Test Taker", icon: "/assets/media/favicon/linkit.ico" },
    Edpuzzle: { name: "Edpuzzle", icon: "/assets/media/favicon/edpuzzle.png" },
    "i-Ready Math": {
      name: "Math To Do, i-Ready",
      icon: "/assets/media/favicon/i-ready.ico",
    },
    "i-Ready Reading": {
      name: "Reading To Do, i-Ready",
      icon: "/assets/media/favicon/i-ready.ico",
    },
    "ClassLink Login": {
      name: "Login",
      icon: "/assets/media/favicon/classlink-login.png",
    },
    "Google Meet": {
      name: "Google Meet",
      icon: "/assets/media/favicon/google-meet.png",
    },
    "Google Docs": {
      name: "Google Docs",
      icon: "/assets/media/favicon/google-docs.ico",
    },
    "Google Slides": {
      name: "Google Slides",
      icon: "/assets/media/favicon/google-slides.ico",
    },
    Wikipedia: {
      name: "Wikipedia",
      icon: "/assets/media/favicon/wikipedia.png",
    },
    Britannica: {
      name: "Encyclopedia Britannica | Britannica",
      icon: "/assets/media/favicon/britannica.png",
    },
    Ducksters: {
      name: "Ducksters",
      icon: "/assets/media/favicon/ducksters.png",
    },
    Minga: {
      name: "Minga – Creating Amazing Schools",
      icon: "/assets/media/favicon/minga.png",
    },
    "i-Ready Learning Games": {
      name: "Learning Games, i-Ready",
      icon: "/assets/media/favicon/i-ready.ico",
    },
    "NoRedInk Home": {
      name: "Student Home | NoRedInk",
      icon: "/assets/media/favicon/noredink.png",
    },
    Desmos: {
      name: "Desmos | Graphing Calculator",
      icon: "/assets/media/favicon/desmos.ico",
    },
    "Newsela Binder": {
      name: "Newsela | Binder",
      icon: "/assets/media/favicon/newsela.png",
    },
    "Newsela Assignments": {
      name: "Newsela | Assignments",
      icon: "/assets/media/favicon/newsela.png",
    },
    "Newsela Home": {
      name: "Newsela | Instructional Content Platform",
      icon: "/assets/media/favicon/newsela.png",
    },
    "PowerSchool Sign In": {
      name: "Student and Parent Sign In",
      icon: "/assets/media/favicon/powerschool.png",
    },
    "PowerSchool Grades and Attendance": {
      name: "Grades and Attendance",
      icon: "/assets/media/favicon/powerschool.png",
    },
    "PowerSchool Teacher Comments": {
      name: "Teacher Comments",
      icon: "/assets/media/favicon/powerschool.png",
    },
    "PowerSchool Standards Grades": {
      name: "Standards Grades",
      icon: "/assets/media/favicon/powerschool.png",
    },
    "PowerSchool Attendance": {
      name: "Attendance",
      icon: "/assets/media/favicon/powerschool.png",
    },
    Nearpod: { name: "Nearpod", icon: "/assets/media/favicon/nearpod.png" },
    StudentVUE: {
      name: "StudentVUE",
      icon: "/assets/media/favicon/studentvue.ico",
    },
    "Quizlet Home": {
      name: "Flashcards, learning tools and textbook solutions | Quizlet",
      icon: "/assets/media/favicon/quizlet.webp",
    },
    "Google Forms Locked Mode": {
      name: "Start your quiz",
      icon: "/assets/media/favicon/googleforms.png",
    },
    DeltaMath: {
      name: "DeltaMath",
      icon: "/assets/media/favicon/deltamath.png",
    },
    Kami: { name: "Kami", icon: "/assets/media/favicon/kami.png" },
    "GoGuardian Admin Restricted": {
      name: "Restricted",
      icon: "/assets/media/favicon/goguardian-lock.png",
    },
    "GoGuardian Teacher Block": {
      name: "Uh oh!",
      icon: "/assets/media/favicon/goguardian.png",
    },
    "World History Encyclopedia": {
      name: "World History Encyclopedia",
      icon: "/assets/media/favicon/worldhistoryencyclopedia.png",
    },
    "Big Ideas Math Assignment Player": {
      name: "Assignment Player",
      icon: "/assets/media/favicon/bim.ico",
    },
    "Big Ideas Math": {
      name: "Big Ideas Math",
      icon: "/assets/media/favicon/bim.ico",
    },
  };

  if (options[selectedValue]) {
    setCloak(options[selectedValue].name, options[selectedValue].icon);
  }

  // Event Key Logic
  const eventKey = JSON.parse(localStorage.getItem("eventKey")) || ["Ctrl", "E"];
  const pLink = localStorage.getItem("pLink") || "https://classroom.google.com/";
  let pressedKeys = [];

  document.addEventListener("keydown", event => {
    pressedKeys.push(event.key);
    if (pressedKeys.length > eventKey.length) {
      pressedKeys.shift();
    }
    if (eventKey.every((key, index) => key === pressedKeys[index])) {
      window.location.href = pLink;
      pressedKeys = [];
    }
  });

  // Function to change wallpaper randomly
  async function changeWallpaper() {
    try {
      // Get list of all image files in the backgrounds folder
      const imageFiles = [
        '0EFA789D-960B-486C-A0BA-42FB40556E73_1_102_o.jpeg',
        '15245569-3A7B-4BF8-A139-B4B322901778_1_105_c.jpeg',
        '152480CD-2B33-4A34-BF4D-E6EFB942DDF4_1_102_o.jpeg',
        '2A79196D-CD3D-4F25-8F84-B90021260309_1_102_o.jpeg',
        '4751ADDF-3805-4823-B49E-C87E9759201B_1_102_o.jpeg',
        '6AB6A75E-A5EB-49CC-BC94-2015EBC62D39_4_5005_c.jpeg',
        '7B120E31-845E-4F40-9135-835190405C4E_1_102_o.jpeg',
        '861A919D-1F91-480F-8272-47DFB0AAAD15_1_102_o.jpeg',
        'A54B1BEE-6D37-4913-BBCB-0F85161C211C_1_102_o.jpeg',
        'A6B18EF6-A72C-4418-AC8F-B27C4E832CFE_1_102_o.jpeg',
        'AA47DBCE-9745-4756-AF2D-C7A9436BD60D_1_102_a.jpeg',
        'C34C1581-4C18-4C64-B3C7-34FA02CC4059_1_102_o.jpeg',
        'CCEF5AD7-D0A8-4A55-958F-7B9950969F10_1_102_o.jpeg',
        'CF626C22-1ADA-408B-A308-8FBA2A5D9B26_1_102_o.jpeg',
        'E2709FB2-1F9D-4AB3-B3F5-A82F71BBD92F_1_102_o.jpeg',
        'E33D4D02-3F69-4089-AB95-45ADC53800C1_1_105_c.jpeg',
        'E94A4093-19E5-4895-8B28-B1600B0DA2D1_1_102_o.jpeg',
        'F3721EB5-F463-40F3-BB73-400A886EEA4D_1_102_o.jpeg',
        'FDBB980D-C10A-413D-B7F1-CDAF8D3A9837_1_102_a.jpeg',
        '1CE7C2EF-3B80-408D-813A-2DC09D5DED0A_1_105_c.jpeg'
      ];
      
      const lastBackground = localStorage.getItem("lastBackgroundImage");
      let randomImage;
      
      do {
        randomImage = imageFiles[Math.floor(Math.random() * imageFiles.length)];
      } while (randomImage === lastBackground && imageFiles.length > 1);

      const backgroundUrl = `/assets/media/background/${randomImage}`;
      document.body.style.backgroundImage = `url('${backgroundUrl}')`;
      localStorage.setItem("backgroundImage", backgroundUrl);
      localStorage.setItem("lastBackgroundImage", randomImage);
    } catch (error) {
      console.error('Error loading background images:', error);
      // Fallback to original hardcoded images
      const backgroundImages = ['a.jpg', 'b.jpg', 'c.jpg', 'd.jpg', 'e.jpg', 'f.jpg', 'g.jpg'];
      const lastBackground = localStorage.getItem("lastBackgroundImage");
      let randomImage;

      do {
        randomImage = backgroundImages[Math.floor(Math.random() * backgroundImages.length)];
      } while (randomImage === lastBackground && backgroundImages.length > 1);

      const backgroundUrl = `/assets/media/background/${randomImage}`;
      document.body.style.backgroundImage = `url('${backgroundUrl}')`;
      localStorage.setItem("backgroundImage", backgroundUrl);
      localStorage.setItem("lastBackgroundImage", randomImage);
    }
  }

  // Background Image Logic - Set initial random background (except on tabs page)
  if (window.location.pathname !== '/d') {
    changeWallpaper();
  }

  // Wallpaper shuffle logic
  if (document.getElementById('menu-audio')) {
    // Index page: change wallpaper when song ends
    const audio = document.getElementById('menu-audio');
    audio.loop = false;
    const audioFiles = ['Bliss.mp3', 'Broken Attachment.mp3', 'Frank Saint.mp3', 'Goodnight Dad I Love You.mp3', 'hide the pain.mp3', 'menu.mp3', 'milk cassette x.mp3', 'old memories of you.mp3', 'pointless.mp3', 'sakura zxc.mp3', 'see you in heaven.mp3', 'Song For Those Who Keep Silent.mp3', 'The Lobotomy.mp3', 'thought you were sweet.mp3'];

    audio.addEventListener('ended', () => {
      changeWallpaper();
      // Select next song
      let currentSrc = audio.querySelector('source').src;
      let currentFile = currentSrc.split('/').pop();
      let currentIndex = audioFiles.indexOf(currentFile);
      let nextIndex = (currentIndex + 1) % audioFiles.length;
      const nextSong = audioFiles[nextIndex];
      const songName = nextSong.replace(/\.mp3$/, '');
      audio.querySelector('source').src = `assets/media/audio/${nextSong}`;
      document.getElementById('song-title').textContent = songName;
      audio.load();
      audio.play();
    });
  } else if (window.location.pathname !== '/d') {
    // Other pages: change wallpaper every 2 minutes (except tabs page)
    setInterval(changeWallpaper, 2 * 60 * 1000);
  }

  // Update version and last updated date
  updateVersion();
  updateLastUpdated();
});
