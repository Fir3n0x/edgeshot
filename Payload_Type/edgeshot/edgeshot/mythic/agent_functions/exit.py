from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class ExitArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        pass


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "Exit the agent: uninstall the extension from the browser (same as kill)."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = ExitArguments
    # builtin=True keeps "exit" in every payload so Mythic's callback-exit flow
    # finds a command named "exit" and stops warning "No exit command selected".
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
