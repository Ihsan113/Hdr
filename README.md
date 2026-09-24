# DanzKu PQ Global Hook v0.2

GitHub Actions build package for the MediaTek PQ global experiment.

Target:
`/vendor/lib64/hw/mt6789/vendor.mediatek.hardware.pq@2.15-impl.so`

First function:
`PictureQuality::enableDisplayColor(unsigned int)`

The repository intentionally builds a guarded native injector scaffold. It
does not claim that remote injection or inline hooking is working until tested
on the target Android 13 device.

Artifact produced by GitHub Actions:
`DanzKu-PQ-Global-Hook-v0.2.zip`
