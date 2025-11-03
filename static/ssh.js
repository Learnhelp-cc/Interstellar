// Web SSH Terminal - Simplified
class WebSSHTerminal {
  constructor(terminalElement, commandInput) {
    this.terminal = terminalElement;
    this.commandInput = commandInput;
    this.history = [];
    this.historyIndex = -1;
    this.currentLine = '';
    this.prompt = '$ ';
    this.initializeTerminal();
  }

  initializeTerminal() {
    this.terminal.value = this.prompt;
    this.terminal.focus();
    this.terminal.setSelectionRange(this.prompt.length, this.prompt.length);
  }

  log(output) {
    const currentContent = this.terminal.value;
    const lines = currentContent.split('\n');
    lines[lines.length - 1] = output;
    lines.push(this.prompt);
    this.terminal.value = lines.join('\n');
    this.terminal.scrollTop = this.terminal.scrollHeight;
    this.terminal.setSelectionRange(this.terminal.value.length, this.terminal.value.length);
  }

  executeCommand(command) {
    if (command.trim()) {
      this.history.push(command);
      this.historyIndex = this.history.length;

      // Simulate command execution
      this.log(`${this.prompt}${command}`);
      setTimeout(() => {
        this.log(`Command executed: ${command}\nOutput would appear here...`);
      }, 500);
    } else {
      this.log(`${this.prompt}${command}`);
    }
  }

  handleKeyDown(event) {
    const key = event.key;

    if (key === 'Enter') {
      event.preventDefault();
      const command = this.getCurrentCommand();
      this.executeCommand(command);
    } else if (key === 'ArrowUp') {
      event.preventDefault();
      if (this.historyIndex > 0) {
        this.historyIndex--;
        this.setCurrentCommand(this.history[this.historyIndex]);
      }
    } else if (key === 'ArrowDown') {
      event.preventDefault();
      if (this.historyIndex < this.history.length - 1) {
        this.historyIndex++;
        this.setCurrentCommand(this.history[this.historyIndex]);
      } else {
        this.historyIndex = this.history.length;
        this.setCurrentCommand('');
      }
    } else if (key === 'Backspace') {
      const currentCommand = this.getCurrentCommand();
      if (currentCommand.length > 0) {
        this.setCurrentCommand(currentCommand.slice(0, -1));
      }
    } else if (key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
      const currentCommand = this.getCurrentCommand();
      this.setCurrentCommand(currentCommand + key);
    }
  }

  getCurrentCommand() {
    const content = this.terminal.value;
    const lines = content.split('\n');
    const lastLine = lines[lines.length - 1];
    return lastLine.startsWith(this.prompt) ? lastLine.slice(this.prompt.length) : '';
  }

  setCurrentCommand(command) {
    const content = this.terminal.value;
    const lines = content.split('\n');
    lines[lines.length - 1] = this.prompt + command;
    this.terminal.value = lines.join('\n');
    this.terminal.setSelectionRange(this.terminal.value.length, this.terminal.value.length);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  const terminal = document.getElementById('ssh-terminal');
  const commandInput = document.getElementById('ssh-command');

  const webSSHTerminal = new WebSSHTerminal(terminal, commandInput);

  terminal.addEventListener('keydown', (event) => webSSHTerminal.handleKeyDown(event));

  // Prevent default behavior for terminal
  terminal.addEventListener('keypress', (event) => event.preventDefault());
  terminal.addEventListener('input', (event) => event.preventDefault());

  // Focus terminal on click
  terminal.addEventListener('click', () => terminal.focus());

  // Connection buttons (simplified)
  document.getElementById('ssh-connect').addEventListener('click', () => {
    const host = document.getElementById('ssh-host').value;
    const username = document.getElementById('ssh-username').value;
    webSSHTerminal.log(`Connecting to ${username}@${host}...`);
    setTimeout(() => {
      webSSHTerminal.log('Connected! Welcome to Web SSH Terminal.');
      webSSHTerminal.log('Type commands below. Use arrow keys for history.');
    }, 1000);
  });

  document.getElementById('ssh-disconnect').addEventListener('click', () => {
    webSSHTerminal.log('Disconnected from SSH server.');
    webSSHTerminal.initializeTerminal();
  });
});
