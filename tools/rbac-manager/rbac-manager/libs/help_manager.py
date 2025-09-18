"""
Help Manager

Manages granular help text for different commands and operations.
"""

from pathlib import Path
from typing import Optional


class HelpManager:
    """Manages help text and documentation"""
    
    def __init__(self):
        self.help_dir = Path(__file__).parent.parent / "help"
    
    def get_help(self, command: str) -> str:
        """Get help text for a specific command"""
        # Convert dashes to underscores for file names
        command_file = command.replace('-', '_')
        help_file = self.help_dir / f"{command_file}_help.txt"
        
        if help_file.exists():
            with open(help_file, 'r') as f:
                return f.read()
        else:
            return f"No help available for command: {command}"
    
    def get_main_help(self) -> str:
        """Get main help text"""
        return self.get_help("main")
    
    def get_examples(self) -> str:
        """Get examples help text"""
        return self.get_help("examples")
    
    def list_available_commands(self) -> list:
        """List all available help commands"""
        help_files = list(self.help_dir.glob("*_help.txt"))
        commands = []
        
        for help_file in help_files:
            command = help_file.stem.replace("_help", "")
            if command != "main":
                commands.append(command)
        
        return sorted(commands)
    
    def show_help(self, command: Optional[str] = None) -> None:
        """Show help for command or main help if no command specified"""
        if command is None:
            print(self.get_main_help())
        else:
            print(self.get_help(command))
    
    def show_examples(self) -> None:
        """Show examples help"""
        print(self.get_examples())
