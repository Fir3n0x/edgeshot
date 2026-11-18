from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class KillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        pass


class KillCommand(CommandBase):
    cmd = "kill"
    needs_admin = False
    help_cmd = "kill"
    description = "Uninstall the extension from the browser (self-removal)."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = KillArguments
    attributes = CommandAttributes(
        builtin=False,
        suggested_command=False,
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
