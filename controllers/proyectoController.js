const Proyecto = require('../models/Proyecto')
const { validationResult } = require('express-validator');

exports.crearProyecto = async (req, res) =>{

    const errors = validationResult(req)
    if( !errors.isEmpty()){
        return res.status(400).json({errores: errors.array()})
    }

    try {
        // crear un nuevo proyecto
        const proyecto = new Proyecto(req.body)

        //Guardar el creador via jwt
        proyecto.creador = req.usuario.id

        //guardar proyecto
        proyecto.save()
        res.json(proyecto)

    } catch (error) { 
        console.log(error)
        res.status(400).send('Hubo un error')
    }
}

//obtiene todos los proyectos del usuario actual 
exports.obtenerProyectos = async (req, res) => {
    try {
        const proyectos = await Proyecto.find({creador: req.usuario.id});
        res.json({ proyectos });

    } catch (error) {
        console.log(error);
        res.status(400).send('Hubo un error')
    }
}

//actualiza un proyecto
exports.actualizarProyecto = async (req, res) => {
    
    const errors = validationResult(req)
    if( !errors.isEmpty()){
        return res.status(400).json({errores: errors.array()})
    }

    const { nombre } = req.body;
    const nuevoProyecto = {};

    if(nombre){
        nuevoProyecto.nombre = nombre;
    }

    try {

        let proyecto = await Proyecto.findById(req.params.id);

        if(!proyecto){
            return res.status(404).json({msg: 'Proyecto no encontrado'});
        }
        if(proyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }

        proyecto = await Proyecto.findByIdAndUpdate({ _id: req.params.id }, { $set: 
            nuevoProyecto}, {new: true });

        return res.json({proyecto});   

    } catch (error) {
        console.log(error);
        res.status(500).send('Hubo un error')
    }
}

//eliminar proyecto
exports.eliminarProyecto = async (req, res) => {
    
    try {

        let proyecto = await Proyecto.findById(req.params.id);

        if(!proyecto){
            return res.status(404).json({msg: 'Proyecto no encontrado'});
        }
        if(proyecto.creador.toString() !== req.usuario.id){
            return res.status(401).json({msg: 'No Autorizado'});
        }

         await Proyecto.findOneAndRemove({ _id: req.params.id });

        return res.json({msg: 'Proyecto eliminado'});   

    } catch (error) {
        console.log(error);
        res.status(500).send('Hubo un error')
    }
}

