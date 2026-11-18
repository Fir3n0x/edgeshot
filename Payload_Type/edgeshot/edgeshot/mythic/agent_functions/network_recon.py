from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class NetworkReconArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class NetworkReconCommand(CommandBase):
    cmd = "network_recon"
    needs_admin = False
    help_cmd = "network_recon"
    description = (
        "Collect network info: local IPs via WebRTC STUN, public IP, country, "
        "ISP and a best-effort VPN detection (public IP vs. WebRTC IP mismatch)."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1016"]
    argument_class = NetworkReconArguments
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
