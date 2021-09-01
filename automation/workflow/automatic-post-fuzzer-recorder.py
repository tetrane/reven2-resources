#!/usr/bin/env python3

"""
This script is an example of automatic, post-fuzzer, REVEN scenario recording and replay,
making the scenario ready for analysis with Axion or the Analysis Python API.

It takes as input a binary and a corpus of files, that typically is a fuzzer's output,
and will record one scenario per corpus file, feeding the binary with the corpus file name
as first argument. Once a record is done, the corresponding replay is launched, and the
next record will be performed. Between each record, the VM's live snapshot will be restored.

Every scenario is named with the prefix given in argument, the binary name, and the corpus
file name. If a scenario with the same name already exists, this script will exit,
meaning you won't overwrite your existing scenarios by re-running it a second time. Also,
this script will not "listen" to the directory, meaning it is not suitable for running
during the fuzzer's execution, but rather after its termination.

DISCLAIMER:
This script is provided as-is, with no guarantee that it will work in your setup.
As it is only an example, many use-cases are not covered on purpose, and all error cases
are not systematically handled. It's still a pretty useful starting point if you need to
go further.
"""

import argparse
import json
from pathlib import Path
from time import sleep

import reven2.preview.project_manager as project_manager


class BinaryRecorder(object):
    def __init__(self, pm_url, snapshot_id, live_snapshot_name):
        self.pm = project_manager.ProjectManager(pm_url)
        self.snapshot = self.pm.get_snapshot(snapshot_id)
        self.live_snapshot_name = live_snapshot_name

        if self.snapshot["type"] != "QEMU":
            print("Automatic record is only available with a QEMU snapshot")
            exit(1)

    def set_binary_file(self, local_binary):
        self.binary_file = self.pm.upload_file(local_binary)
        print(
            'binary file "%s" uploaded with id %s'
            % (self.binary_file["name"], self.binary_file["id"])
        )

    def set_input_file(self, input_file):
        self.input_file = self.pm.upload_file(input_file)
        print(
            'input file "%s" uploaded with id %s'
            % (self.input_file["name"], self.input_file["id"])
        )

    def create_scenario(self, name_prefix="automatic scenario", description=""):
        name = "%s - %s - %s" % (
            name_prefix,
            self.binary_file["name"],
            self.input_file["name"],
        )
        self.scenario = self.pm.create_scenario(
            name,
            self.snapshot["id"],
            description=description,
        )
        self.scenario = self.pm.update_scenario(
            self.scenario["id"],
            input_files=[
                self.binary_file["id"],
                self.input_file["id"],
            ],
        )
        print(
            'Scenario "%s" created with id %d'
            % (self.scenario["name"], self.scenario["id"])
        )

    def start_session(self):
        response = self.pm.start_qemu_snapshot_session(
            self.snapshot["id"], live_snapshot=self.live_snapshot_name
        )
        self.session = response["session"]
        print(response["message"])

    def stop_session(self):
        response = self.pm.stop_session(self.session["id"])
        print(response["message"])
        self.session = None

    def record_scenario(self, timeout_start=None, timeout_record=None):
        params = {
            "qemu_session_id": self.session["id"],
        }

        if timeout_start:
            params["timeout_start"] = int(timeout_start)
        if timeout_record:
            params["timeout_record"] = int(timeout_record)

        params["binary_name"] = self.binary_file["id"]
        params["autorun_binary"] = self.binary_file["id"]
        params["autorun_files"] = [self.input_file["id"]]
        params["autorun_args"] = ["C:\\reven\\%s" % self.input_file["name"]]

        auto_record_task = None
        try:
            response = self.pm.load_live_snapshot_qemu_session(
                self.session["id"], live_snapshot_name=self.live_snapshot_name
            )
            print(response["message"])

            auto_record_task = self.pm.auto_record_binary(**params)["task"]
            print("Record started")

            while not auto_record_task["finished"]:
                sleep(3)

                # retrieve the task with updated information
                auto_record_task = self.pm.get_task(auto_record_task["id"])
                print(
                    "Recorder status: %s"
                    % auto_record_task["display_recorder_status"].rjust(18),
                    end="\r",
                )
            print("")

            try:
                if auto_record_task["status"] in ["ABORTED", "FAILURE"]:
                    raise RuntimeError(
                        "Auto-record failed: %s" % auto_record_task["fail_reason"]
                    )

                # Commit the record into the scenario
                response = self.pm.commit_record(
                    self.session["id"],
                    self.scenario["id"],
                    record=auto_record_task["record_name"],
                )
                print(response["message"])

                # When using the autorun, the files are copied into "C:\\reven" on Windows
                self.scenario = self.pm.update_scenario(
                    self.scenario["id"], cdrom_mount_point="C:\\reven"
                )

            finally:
                auto_record_task = None

        finally:
            if auto_record_task is not None:
                response = self.pm.cancel_task(auto_record_task["id"])
                print(response["message"])

    def replay_scenario(self, resources=None, actions=None):
        if resources is None:
            resources = [
                resource["name"]
                for resource in self.pm.get_resources_list()
                if not resource["deprecated"]
            ]
        if actions is None:
            actions = [action["name"] for action in self.pm.get_actions_list()]

        self.pm.replay_scenario(
            self.scenario["id"], resources=resources, actions=actions
        )
        print("Replay started for scenario %d" % self.scenario["id"])

        # retrieve the scenario with replay status in it
        self.scenario = self.pm.get_scenario(self.scenario["id"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fully automated scenario creation")

    parser.add_argument(
        "--url", required=True, help="The URL of the Reven project manager"
    )
    parser.add_argument(
        "--snapshot",
        type=int,
        required=True,
        help="The id of the snapshot to use for the scenario",
    )
    parser.add_argument(
        "--live-snp", required=True, help="Name of the live snapshot to use"
    )
    parser.add_argument(
        "--name",
        default="automatic-binary-scenario",
        help="The name of the scenario to create",
    )
    parser.add_argument("--description", default="", help="Description of the scenario")
    parser.add_argument(
        "--corpus", required=True, help="Local path to the corpus of inputs"
    )
    parser.add_argument(
        "--local-binary", required=True, help="Local path of the binary to record"
    )
    parser.add_argument(
        "--args", default=None, nargs="+", help="Args to give to the binary"
    )
    parser.add_argument(
        "--timeout-start",
        type=int,
        help="The maximum number of seconds to wait between the readiness of the recorder and the start of the record",
    )
    parser.add_argument(
        "--timeout-record",
        type=int,
        help="The maximum number of seconds to wait when recording before stopping it",
    )
    parser.add_argument(
        "--resources",
        default=None,
        nargs="+",
        help="Specific resources you want to replay. By default replay all",
    )
    parser.add_argument(
        "--actions",
        default=None,
        nargs="+",
        help="Specific actions you want to replay. By default replay all",
    )

    args = parser.parse_args()

    recorded_scenarios = []

    recorder = BinaryRecorder(args.url, args.snapshot, args.live_snp)
    recorder.set_binary_file(args.local_binary)
    recorder.start_session()
    try:
        for input_file in Path(args.corpus).iterdir():
            if "README" not in str(input_file):
                recorder.set_input_file(str(input_file))
                recorder.create_scenario(name_prefix=args.name)
                recorder.record_scenario(timeout_start=args.timeout_start, timeout_record=args.timeout_record)
                recorder.replay_scenario(args.resources, args.actions)
                recorded_scenarios.append(recorder.scenario)
                print("")
        print("All files from the corpus were recorded, exiting.")
    finally:
        recorder.stop_session()
        Path("created_scenarios.json").write_text(json.dumps(recorded_scenarios))
        print("Created scenarios have been dumped to 'created_scenarios.json'")
