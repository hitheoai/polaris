"""Pull-request integration: plan review comments offline, then publish them to a forge.

`polaris pr plan` reviews a pull request's commits (nothing from the pull request is checked
out, built or executed) and writes a bounded, inert plan. `polaris pr publish` validates that
plan against the trusted event and posts it with the job's token. Findings are evidence for
review, never approval to merge or proof of safety.
"""
