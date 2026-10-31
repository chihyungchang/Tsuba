"""Model and render the Tsuba guard for the App icon.

Run: Blender -b -P tsuba.py -- <out.png> [icon|art]
- icon (default): the guard tilted, with its cast shadow, on a transparent background; compose.swift puts it on the icon plate.
- art: the guard facing the camera with no shadow, for the dashboard animation (app/src/assets/tsuba.png); CSS adds its own tilt.
The outline matches tray-template.svg (a four-lobed mokko guard) in 1024-pixel icon coordinates.

Regenerate the icon set (from app/):
  Blender -b -P src-tauri/icons/source/tsuba.py -- /tmp/guard.png
  swift src-tauri/icons/source/compose.swift /tmp/guard.png /tmp/icon.png
  pnpm tauri icon /tmp/icon.png        # then delete the android/, ios/ and 64x64.png it adds
  Blender -b -P src-tauri/icons/source/tsuba.py -- "$PWD/src/assets/tsuba.png" art
  pnpm tauri icon src-tauri/icons/source/tray-template.svg --png 44 -o /tmp/tray   # -> icons/tray-template.png;
  # the paused one is the same SVG with fill-opacity=".45" -> icons/tray-template-paused.png
"""

import math
import sys

import bpy

ARGS = sys.argv[sys.argv.index("--") + 1 :]
OUT = ARGS[0]
IS_ART = ARGS[1:] == ["art"]


def to_world(x, y):
    """Icon pixels (1024 canvas, y down) to Blender units (canvas spans -1..1)"""
    return ((x - 512) / 512, -(y - 512) / 512)


def mokko(scale=1.0, steps=256):
    """Four circles of radius r, d from the center: the outline is the farthest circle along each ray"""
    d, r = 123 * scale, 205 * scale
    points = []
    for i in range(steps):
        a = i * math.tau / steps
        ux, uy = math.cos(a), math.sin(a)
        reach = max(u_dot_c + math.sqrt(u_dot_c**2 - d * d + r * r) for u_dot_c in (ux * cx + uy * cy for cx, cy in [(0, -d), (d, 0), (0, d), (-d, 0)]))
        points.append((512 + reach * ux, 512 + reach * uy))
    return points


def bezier(p0, p1, p2, p3=None, steps=16):
    out = []
    for i in range(steps):
        t = i / steps
        if p3 is None:
            x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0]
            y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]
        else:
            x = (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * p1[0] + 3 * (1 - t) * t * t * p2[0] + t**3 * p3[0]
            y = (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * p1[1] + 3 * (1 - t) * t * t * p2[1] + t**3 * p3[1]
        out.append((x, y))
    return out


# The tang hole (nakago-ana) and the two side holes (kozuka and kogai hitsu-ana), same as tray-template.svg
NAKAGO = bezier((499, 424), (512, 404), (525, 424)) + bezier((525, 424), (534, 510), (544, 596), steps=4) + bezier((544, 596), (512, 612), (480, 596)) + bezier((480, 596), (490, 510), (499, 424), steps=4)
KOZUKA = bezier((432, 444), (392, 462), (392, 562), (432, 580)) + bezier((432, 580), (432, 512), (432, 444), steps=4)
KOGAI = (
    bezier((592, 444), (624, 452), (634, 484), (620, 504))
    + bezier((620, 504), (615, 512), (620, 520), steps=6)
    + bezier((620, 520), (634, 540), (624, 572), (592, 580))
    + bezier((592, 580), (592, 512), (592, 444), steps=4)
)
SEPPA = [(512 + 62 * math.cos(a), 510 + 128 * math.sin(a)) for a in (i * math.tau / 96 for i in range(96))]


def plate(name, outlines, z, depth, bevel, material):
    curve = bpy.data.curves.new(name, "CURVE")
    curve.dimensions = "2D"
    curve.fill_mode = "BOTH"
    curve.extrude = depth
    curve.bevel_depth = bevel
    curve.bevel_resolution = 4
    for outline in outlines:
        spline = curve.splines.new("POLY")
        spline.points.add(len(outline) - 1)
        for point, (x, y) in zip(spline.points, outline):
            point.co = (*to_world(x, y), 0, 1)
        spline.use_cyclic_u = True
    obj = bpy.data.objects.new(name, curve)
    obj.location.z = z
    obj.data.materials.append(material)
    bpy.context.collection.objects.link(obj)
    return obj


def metal(name, color, roughness, hammered):
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    nodes, links = mat.node_tree.nodes, mat.node_tree.links
    bsdf = nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (*color, 1)
    bsdf.inputs["Metallic"].default_value = 1
    bsdf.inputs["Roughness"].default_value = roughness
    if hammered:
        # Hammer marks on forged iron: a soft bumpy surface rather than a mirror
        noise = nodes.new("ShaderNodeTexNoise")
        noise.inputs["Scale"].default_value = 60
        noise.inputs["Detail"].default_value = 6
        bump = nodes.new("ShaderNodeBump")
        bump.inputs["Strength"].default_value = hammered
        links.new(noise.outputs["Fac"], bump.inputs["Height"])
        links.new(bump.outputs["Normal"], bsdf.inputs["Normal"])
    return mat


bpy.ops.wm.read_factory_settings(use_empty=True)
scene = bpy.context.scene

iron = metal("iron", (0.035, 0.035, 0.04), 0.34, 0.5)
seppa_iron = metal("seppa", (0.04, 0.04, 0.045), 0.28, 0.15)
gold = metal("gold", (1.0, 0.6, 0.16), 0.24, 0)

holes = [NAKAGO, KOZUKA, KOGAI]
guard = [
    plate("rim", [mokko(1.0), mokko(0.925)], 0.0, 0.05, 0.02, gold),
    plate("body", [mokko(0.935)] + holes, 0.0, 0.032, 0.006, iron),
    plate("seppa", [SEPPA, NAKAGO], 0.03, 0.03, 0.008, seppa_iron),
]
# A little tilt shows the thickness of the iron at the edges and inside the holes
pivot = bpy.data.objects.new("pivot", None)
bpy.context.collection.objects.link(pivot)
for obj in guard:
    obj.parent = pivot
pivot.rotation_euler = (math.radians(-3), math.radians(2), 0) if IS_ART else (math.radians(-8), 0, 0)
pivot.location.z = 0.1

if not IS_ART:
    bpy.ops.mesh.primitive_plane_add(size=6)
    bpy.context.active_object.is_shadow_catcher = True

for name, location, energy, size in [("key", (-0.5, 3.0, 3.0), 800, 2.6), ("fill", (2.8, -1.4, 2.4), 120, 3.5), ("top", (0, 0.4, 5), 60, 5)]:
    light = bpy.data.lights.new(name, "AREA")
    light.energy, light.size = energy, size
    obj = bpy.data.objects.new(name, light)
    obj.location = location
    direction = -obj.location.normalized()
    obj.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
    bpy.context.collection.objects.link(obj)

world = bpy.data.worlds.new("world")
world.use_nodes = True
world.node_tree.nodes["Background"].inputs["Color"].default_value = (0.2, 0.16, 0.14, 1)
world.node_tree.nodes["Background"].inputs["Strength"].default_value = 0.6
scene.world = world

camera = bpy.data.cameras.new("camera")
camera.type = "ORTHO"
# The art crops to the guard (it spans about -0.68..0.68 with the bevel). # The icon leaves the guard about 72% of the plate: at 2 units it filled 82% and looked cramped in the Dock
camera.ortho_scale = 1.42 if IS_ART else 2.28
cam = bpy.data.objects.new("camera", camera)
cam.location = (0, 0, 6)
bpy.context.collection.objects.link(cam)
scene.camera = cam

scene.render.engine = "CYCLES"
scene.cycles.samples = 128
scene.cycles.use_denoising = True
scene.render.film_transparent = True
# Standard keeps the gold and the plate saturated; AgX washes both out
scene.view_settings.view_transform = "Standard"
scene.render.resolution_x = scene.render.resolution_y = 560 if IS_ART else 1024
scene.render.image_settings.file_format = "PNG"
scene.render.image_settings.color_mode = "RGBA"
scene.render.filepath = OUT
bpy.ops.render.render(write_still=True)
