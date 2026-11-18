from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class CheckRceArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        # check_rce takes no arguments.
        self._args = []

    async def parse_arguments(self):
        pass


class CheckRceCommand(CommandBase):
    cmd = "check_rce"
    needs_admin = False
    help_cmd = "check_rce"
    description = (
        "Ping the Native Messaging host (com.site.agent) to check whether RCE "
        "is available on the victim. Only functional when the payload was built "
        "with enable_rce=true."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1059"]
    argument_class = CheckRceArguments
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
