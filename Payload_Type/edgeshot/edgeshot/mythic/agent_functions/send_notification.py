from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class SendNotificationArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class SendNotificationCommand(CommandBase):
    cmd = "send_notification"
    needs_admin = False
    help_cmd = "send_notification"
    description = (
        "Show the configured notification lure (set via set_notification) to the "
        "victim with a persistent interaction prompt."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1204"]
    argument_class = SendNotificationArguments
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
