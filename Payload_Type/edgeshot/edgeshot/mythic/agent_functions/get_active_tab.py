from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class GetActiveTabArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        pass


class GetActiveTabCommand(CommandBase):
    cmd = "get_active_tab"
    needs_admin = False
    help_cmd = "get_active_tab"
    description = "Return the URL and title of the currently active tab."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = GetActiveTabArguments
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
