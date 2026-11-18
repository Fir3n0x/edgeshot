from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class GetDomArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="tab_id",
                type=ParameterType.Number,
                description="ID of the tab to dump (0 or empty = active tab)",
                default_value=0,
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class GetDomCommand(CommandBase):
    cmd = "get_dom"
    needs_admin = False
    help_cmd = "get_dom [tab_id]"
    description = "Return the DOM (outerHTML) of a tab. Defaults to the active tab."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = GetDomArguments
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
