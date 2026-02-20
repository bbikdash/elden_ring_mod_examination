# Attempt to Upgrade [`Unlocked Unique Skills`](https://www.nexusmods.com/eldenring/mods/1410) by cleverraptor6 to Elden Ring v1.16.1

As the title says, this repo and scripting was an attempt to update Clever's mod to the latest version of Elden Ring. Unfortunately, at the time of writing I was not successful.

I've isolated a lot of the changes Clever made to the CSV files in [unlocked_unique_skills_free_v1.16.1/](./data/unlocked_unique_skills_free_v1.16.1/) by remapping the colliding values from the v1.06 mod to unused values in v1.16 of Elden Ring. However, when I package them into the `regulation.bin`, Seamless_Coop complains that the save file is corrupted indicating that the `regulation.bin` is malformed and not created properly.

If someone who knows more about Elden Ring modding in general and about how IDs should be mapped, feel free to take a crack at it.
