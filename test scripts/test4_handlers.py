import bpy

def auto_execute():
    print("This would auto-execute")

bpy.app.handlers.load_post.append(auto_execute)