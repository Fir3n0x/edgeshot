# ============================================================================
# heartbeat — minimal builtin command.
#
# CANONICAL PATTERN for every EdgeShot command (milestone 2):
#   - a <Cmd>Arguments(TaskArguments) class that initializes self._args
#     (list of CommandParameter) and defines parse_arguments();
#   - a <Cmd>Command(CommandBase) class with argument_class = <Cmd>Arguments.
#
# IMPORTANT: argument_class must NEVER be None, otherwise Mythic crashes while
#   parsing arguments (task.args becomes None -> AttributeError).
# ============================================================================
from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class HeartbeatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        # List (potentially empty) of this command's parameters.
        # To add a parameter: self._args = [CommandParameter(name=..., type=...)]
        self._args = []

    async def parse_arguments(self):
        # heartbeat takes no arguments: nothing to parse.
        pass


class HeartbeatCommand(CommandBase):
    cmd = "heartbeat"
    needs_admin = False
    help_cmd = "heartbeat"
    description = "Check that the extension is alive and return its status."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = HeartbeatArguments
    attributes = CommandAttributes(
        builtin=True,
        suggested_command=False,
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
