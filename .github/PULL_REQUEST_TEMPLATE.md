## Summary

<!-- One or two sentences describing the change and why it is needed. -->

## Related issues

<!-- Link to any related GitHub issues using "Closes #123" or "Refs #123". -->

## Checklist

- [ ] Code builds with zero warnings (`make`)
- [ ] All tests pass (`make test`)
- [ ] Code style is applied (`make style`; `git diff --exit-code` passes)
- [ ] Quality gate passes (`make cppcheck`, `make lizard`)
- [ ] Line coverage remains ≥ 80 % (`make coverage`)
- [ ] Bug prevention checklist reviewed (see `QA.md §Bug Prevention`)
- [ ] TODO.md updated (bullets ticked, completed sections removed)
- [ ] DOMAIN.md updated if CLI, architecture, or business rules changed
- [ ] Man pages are consistent with the code
