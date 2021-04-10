const Tarea = require('../models/Tarea')
const Proyecto = require('../models/Proyecto')
const { validationResult } = require('express-validator');

exports.crearTarea = async (req, res) =>{

    const errors = validationResult(req)
    if( !errors.isEmpty()){
        return res.status(400).json({errores: errors.array()})
    }

    const { proyecto } = req.body;
    
    try {
        const findProyecto = await Proyecto.findById(proyecto)
        if(!findProyecto){
            return res.status(404).json({msg: "Proyecto no encontrado"})
        }

        if(findProyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }

        const tarea = new Tarea(req.body);
        await tarea.save();

        res.json({tarea});

    } catch (error) { 
        console.log(error)
        res.status(500).send('Hubo un error')
    }
}

exports.obtenerTareas = async (req, res) =>{

    
    try {
        const { proyecto } = req.query;

        const findProyecto = await Proyecto.findById(proyecto)
        if(!findProyecto){
            return res.status(404).json({msg: "Proyecto no encontrado"})
        }

        if(findProyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }

        const tareas = await Tarea.find({ proyecto}).sort({creado: -1})

        res.json({tareas});

    } catch (error) { 
        console.log(error)
        res.status(500).send('Hubo un error')
    }
}

exports.actualizarTarea = async (req, res) =>{
   
    try {
        const { proyecto, nombre, estado } = req.body;

        let tarea = await Tarea.findById(req.params.id);
        if(!tarea){
            return res.status(404).json({msg: 'No existe esa tarea'});
        }

        const findProyecto = await Proyecto.findById(proyecto)
        if(findProyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }

        const nuevaTarea = {};
          nuevaTarea.nombre = nombre;
          nuevaTarea.estado = estado;
        
        tarea = await Tarea.findOneAndUpdate({ _id: req.params.id }, nuevaTarea, {new: true });

        res.json({tarea});

    } catch (error) { 
        console.log(error)
        res.status(500).send('Hubo un error')
    }
}
exports.eliminarTarea = async (req, res) =>{
   
    try {
        const { proyecto } = req.query;

        let tarea = await Tarea.findById(req.params.id);
        if(!tarea){
            return res.status(404).json({msg: 'No existe esa tarea'});
        }

        const findProyecto = await Proyecto.findById(proyecto)
        if(findProyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }
        
        await Tarea.findOneAndRemove({ _id: req.params.id });

        res.json({msg: 'Tarea Eliminada'});

    } catch (error) { 
        console.log(error)
        res.status(500).send('Hubo un error')
    }
}