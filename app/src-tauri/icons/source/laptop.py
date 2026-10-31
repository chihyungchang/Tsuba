"""Model and render the laptop the dashboard guardian stands on.

Run (from app/): Blender -b -P src-tauri/icons/source/laptop.py -- "$PWD/src/assets/laptop.png"
Renders a graphite laptop with an empty dark screen, with its contact shadow, on a transparent background.
The camera looks straight at the screen, so the screen is an exact rectangle in the image: the script prints
its position as percentages of the frame, and .guardian-screen in App.css must use them (the tsuba and the code are drawn there in CSS).
Same materials and light as tsuba.py, so the laptop and the guard look like one object.
"""

import math
import sys

import bpy
from bpy_extras.object_utils import world_to_camera_view
from mathutils import Vector

OUT = sys.argv[sys.argv.index("--") + 1]
# The frame is 1.4x the laptop's box, so its shadow fades out inside the image instead of being cut at the edge;
# .guardian-stage in App.css is 140% of the guardian to match
MARGIN = 1.4
SIZE = 840
TILT = math.radians(20)  # the lid leans back this far from vertical


def material(name, color, metallic, roughness, emission=None):
    mat = bpy.data.materials.new(name)
    mat.use_nodes = True
    bsdf = mat.node_tree.nodes["Principled BSDF"]
    bsdf.inputs["Base Color"].default_value = (*color, 1)
    bsdf.inputs["Metallic"].default_value = metallic
    bsdf.inputs["Roughness"].default_value = roughness
    if emission:
        # A matte screen: CSS draws over it, so it must not carry reflections the overlay would cut off
        bsdf.inputs["Specular IOR Level"].default_value = 0
        bsdf.inputs["Emission Color"].default_value = (*emission, 1)
        bsdf.inputs["Emission Strength"].default_value = 1
    return mat


def box(name, size, location, mat, bevel, parent=None):
    bpy.ops.mesh.primitive_cube_add(size=1, location=location)
    obj = bpy.context.active_object
    obj.name = name
    obj.scale = size
    bpy.ops.object.transform_apply(scale=True)
    modifier = obj.modifiers.new("bevel", "BEVEL")
    modifier.width, modifier.segments = bevel, 4
    bpy.ops.object.shade_smooth()
    obj.data.materials.append(mat)
    if parent:
        obj.parent = parent
    return obj


bpy.ops.wm.read_factory_settings(use_empty=True)
scene = bpy.context.scene

graphite = material("graphite", (0.09, 0.09, 0.1), 1, 0.38)
keycap = material("keycap", (0.02, 0.02, 0.025), 0, 0.55)
glass = material("bezel", (0.004, 0.004, 0.005), 0, 0.08)
screen = material("screen", (0, 0, 0), 0, 1, emission=(0.012, 0.013, 0.02))
gold = material("gold", (1.0, 0.6, 0.16), 1, 0.24)

# Base: front edge at y = -1, hinge at the back (y = 1)
box("base", (3.0, 2.0, 0.08), (0, 0, 0.04), graphite, 0.035)
box("keyboard well", (2.5, 0.92, 0.01), (0, 0.42, 0.081), keycap, 0.004)
for row in range(5):
    for col in range(14):
        box(f"key{row}-{col}", (0.148, 0.148, 0.018), (-1.17 + col * 0.18, 0.06 + row * 0.18, 0.088), keycap, 0.02)
box("trackpad", (1.05, 0.62, 0.004), (0, -0.52, 0.081), graphite, 0.03)

# Lid: an empty pivots at the hinge, so the lid is built upright and then leaned back
hinge = bpy.data.objects.new("hinge", None)
bpy.context.collection.objects.link(hinge)
hinge.location = (0, 0.985, 0.08)
box("lid", (3.0, 0.05, 1.95), (0, 0.025, 0.975), graphite, 0.035, hinge)
box("bezel", (2.96, 0.006, 1.91), (0, -0.003, 0.975), glass, 0.03, hinge)
box("screen", (2.74, 0.004, 1.66), (0, -0.007, 1.03), screen, 0.0, hinge)
# A thin gold line under the screen: the guard's rim color carried onto the machine
box("accent", (0.5, 0.004, 0.012), (0, -0.007, 0.12), gold, 0.002, hinge)
hinge.rotation_euler.x = -TILT

bpy.ops.mesh.primitive_plane_add(size=30)
bpy.context.active_object.is_shadow_catcher = True

for name, location, energy, size in [("key", (-2, -7, 9), 2600, 5), ("fill", (6, -5, 3), 700, 6), ("top", (0, 2, 9), 500, 8)]:
    light = bpy.data.lights.new(name, "AREA")
    light.energy, light.size = energy, size
    # Only the key light casts a shadow: the low fill light threw a long soft one past the edge of the frame
    light.use_shadow = name == "key"
    obj = bpy.data.objects.new(name, light)
    obj.location = location
    obj.rotation_euler = (-obj.location.normalized()).to_track_quat("-Z", "Y").to_euler()
    bpy.context.collection.objects.link(obj)

world = bpy.data.worlds.new("world")
world.use_nodes = True
world.node_tree.nodes["Background"].inputs["Color"].default_value = (0.2, 0.16, 0.14, 1)
world.node_tree.nodes["Background"].inputs["Strength"].default_value = 0.6
scene.world = world

# The camera looks along the screen's normal, so the screen stays a rectangle; the lens shift moves the laptop to the middle
bpy.context.view_layer.update()
screen_obj = bpy.data.objects["screen"]
center = screen_obj.matrix_world.translation
normal = Vector((0, -math.cos(TILT), math.sin(TILT)))
camera = bpy.data.cameras.new("camera")
camera.lens = 85
camera.shift_y = 0.1 / MARGIN
cam = bpy.data.objects.new("camera", camera)
cam.location = center + normal * 10.4 * MARGIN
cam.rotation_euler = (-normal).to_track_quat("-Z", "Y").to_euler()
bpy.context.collection.objects.link(cam)
scene.camera = cam

scene.render.engine = "CYCLES"
scene.cycles.samples = 128
scene.cycles.use_denoising = True
scene.render.film_transparent = True
scene.view_settings.view_transform = "Standard"
scene.render.resolution_x = scene.render.resolution_y = SIZE
scene.render.image_settings.file_format = "PNG"
scene.render.image_settings.color_mode = "RGBA"
scene.render.filepath = OUT

bpy.context.view_layer.update()
corners = [screen_obj.matrix_world @ Vector(c) for c in screen_obj.bound_box]
points = [world_to_camera_view(scene, cam, c) for c in corners]
left, right = min(p.x for p in points), max(p.x for p in points)
top, bottom = 1 - max(p.y for p in points), 1 - min(p.y for p in points)
print(f"SCREEN left {left:.2%} top {top:.2%} width {right - left:.2%} height {bottom - top:.2%}")
bpy.ops.render.render(write_still=True)
