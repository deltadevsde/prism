# Idea 2: Accounts From Web Sources
> Note: This is only a rough outline and will be expanded upon with verified interest.

## Problem
Every time users join a new platform, they face the challenge of starting from scratch to build their network and establish trust in their identity. This fragmentation creates friction in maintaining relationships across digital spaces and verifying authenticity.

The hackathon track aims to solve this by enabling users to connect their social media accounts to Prism, bridging their identities into a unified profile. This ensures their contacts can easily verify and locate them across platforms.

## Solution
The first iteration of bringing external accounts into Prism can use the reclaim protocol.

The project has these rough requirements:
1. Provide a frontend that allows a user to create a reclaim proof with an external account source (e.g. Twitter)
2. Create a prism service that lets users create prism accounts using a valid reclaim proof using the `AddData` operation.

## Resources
- [Reclaim Protocol](https://www.reclaimprotocol.org)
- [Prism Account Sources](../labels.md)
